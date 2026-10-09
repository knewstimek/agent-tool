package analyze

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// decompilePoolSize bounds the idle workers kept loaded: each holds a
	// whole program (up to the heap limit).
	decompilePoolSize = 2
)

// decompileIdle retires a worker no request has used for this long.
var decompileIdle = 2 * time.Minute

// decompWorker is a running worker process serving requests one at a time.
type decompWorker struct {
	key      string // binary identity: path, pdb_path, size, mtime
	cmd      *exec.Cmd
	guard    *workerGuard
	guardErr error
	stdin    io.WriteCloser
	lines    chan decompileLine // closed when the worker's stdout ends
	stderr   *limitedBuffer
	busy     bool
	idle     *time.Timer
}

// workerPool holds the running workers.
type workerPool struct {
	mu      sync.Mutex
	workers []*decompWorker
}

var decompPool workerPool

// workerKey identifies a binary for reuse: a rebuilt file (other size or
// time) gets a fresh worker.
func workerKey(req decompileRequest) string {
	key := fmt.Sprintf("%s|%s|%t", req.Path, req.PDBPath, req.PDBForce)
	if fi, err := os.Stat(req.Path); err == nil {
		key += fmt.Sprintf("|%d|%d", fi.Size(), fi.ModTime().UnixNano())
	}
	return key
}

// acquireWorker returns an idle worker for key or starts one.
func acquireWorker(key string) (*decompWorker, error) {
	decompPool.mu.Lock()
	for _, w := range decompPool.workers {
		if !w.busy && w.key == key {
			w.busy = true
			w.idle.Stop()
			decompPool.mu.Unlock()
			return w, nil
		}
	}
	// Make room: retire idle workers beyond the pool size, oldest first.
	var keep []*decompWorker
	idleCount := 0
	for _, w := range decompPool.workers {
		if !w.busy {
			idleCount++
		}
	}
	for _, w := range decompPool.workers {
		if !w.busy && idleCount >= decompilePoolSize {
			idleCount--
			w.idle.Stop()
			go w.retire()
			continue
		}
		keep = append(keep, w)
	}
	decompPool.workers = keep
	decompPool.mu.Unlock()

	w, err := startWorker(key)
	if err != nil {
		return nil, err
	}
	decompPool.mu.Lock()
	decompPool.workers = append(decompPool.workers, w)
	decompPool.mu.Unlock()
	return w, nil
}

func startWorker(key string) (*decompWorker, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot locate the agent-tool executable to start the decompile worker: %w", err)
	}
	cmd := exec.Command(exe, DecompileWorkerArg)
	prepareWorker(cmd)
	w := &decompWorker{key: key, cmd: cmd, stderr: &limitedBuffer{}, busy: true, lines: make(chan decompileLine)}
	cmd.Stderr = w.stderr
	if w.stdin, err = cmd.StdinPipe(); err != nil {
		return nil, fmt.Errorf("decompile worker pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("decompile worker pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cannot start decompile worker: %w", err)
	}
	w.guard, w.guardErr = guardWorker(cmd.Process, uint64(decompileMemLimitMB+decompileJobHeadroomMB)<<20)
	w.idle = time.AfterFunc(time.Hour, func() {})
	w.idle.Stop()
	go func() {
		defer close(w.lines)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 256<<20) // one line carries a whole function's C
		for sc.Scan() {
			var l decompileLine
			if json.Unmarshal(sc.Bytes(), &l) == nil {
				w.lines <- l
			}
		}
	}()
	return w, nil
}

// release returns a healthy worker to the pool, or ends a broken one.
func (w *decompWorker) release(healthy bool) {
	if !healthy {
		w.kill()
		return
	}
	decompPool.mu.Lock()
	defer decompPool.mu.Unlock()
	w.busy = false
	w.idle = time.AfterFunc(decompileIdle, func() {
		decompPool.mu.Lock()
		if w.busy {
			decompPool.mu.Unlock()
			return
		}
		decompPool.remove(w)
		decompPool.mu.Unlock()
		w.retire()
	})
}

// remove drops w from the pool; the caller holds mu.
func (p *workerPool) remove(w *decompWorker) {
	for i, o := range p.workers {
		if o == w {
			p.workers = append(p.workers[:i], p.workers[i+1:]...)
			return
		}
	}
}

// retire ends an idle worker: closing its input lets it exit on its own;
// one that does not is killed. It is always reaped and its job closed.
func (w *decompWorker) retire() {
	_ = w.stdin.Close()
	done := make(chan struct{})
	go func() {
		for range w.lines { // drain until the worker's output ends
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		w.guard.kill()
		<-done
	}
	_ = w.cmd.Wait()
	w.guard.close()
}

// kill ends a worker now and removes it from the pool.
func (w *decompWorker) kill() {
	decompPool.mu.Lock()
	decompPool.remove(w)
	decompPool.mu.Unlock()
	w.guard.kill()
	for range w.lines {
	}
	_ = w.cmd.Wait()
	w.guard.close()
}

// runDecompileWorker sends one request to a pooled worker (starting it if
// needed) and collects its lines until the request is done, the timeout
// fires or the client cancels. failure describes an abnormal end ("" when
// the request finished); a worker that ended abnormally is reaped and
// dropped from the pool.
func runDecompileWorker(ctx context.Context, req decompileRequest, timeout time.Duration) ([]decompileLine, string) {
	w, err := acquireWorker(workerKey(req))
	if err != nil {
		return nil, err.Error()
	}
	body, _ := json.Marshal(req)
	if _, err := w.stdin.Write(append(body, '\n')); err != nil {
		w.kill()
		return nil, "cannot send the request to the decompile worker: " + err.Error()
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var lines []decompileLine
	for {
		select {
		case l, ok := <-w.lines:
			if !ok { // the worker exited before finishing the request
				waitErr := w.cmd.Wait()
				w.guard.close()
				decompPool.mu.Lock()
				decompPool.remove(w)
				decompPool.mu.Unlock()
				if hasFatal(lines) {
					return lines, ""
				}
				failure := fmt.Sprintf("worker exited abnormally (%v)", waitErr)
				if s := strings.TrimSpace(w.stderr.String()); s != "" {
					failure += ": " + firstLine(s)
				}
				if w.guardErr == nil {
					failure += "; it may have hit the memory limit"
				}
				return lines, failure
			}
			if l.Kind == "done" {
				w.release(!hasFatal(lines))
				return lines, ""
			}
			lines = append(lines, l)
		case <-timer.C:
			w.kill()
			return lines, fmt.Sprintf("timed out after %s", timeout)
		case <-ctx.Done():
			w.kill()
			return lines, "cancelled by the client"
		}
	}
}
