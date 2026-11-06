//go:build !windows

package common

import (
	"os"
	"sync"
	"syscall"
)

// ProcessGuard kills a process group. The caller must start the process with
// Setpgid so the group id equals the pid. Unix has no portable
// kill-on-parent-exit; KillOnClose and MemoryLimit are Windows job features
// and are ignored here (Linux callers use the parent-death signal instead).
type ProcessGuard struct {
	mu     sync.Mutex
	proc   *os.Process
	closed bool
}

type GuardOptions struct {
	KillOnClose bool
	MemoryLimit uint64
}

func GuardProcess(p *os.Process, _ GuardOptions) (*ProcessGuard, error) {
	return &ProcessGuard{proc: p}, nil
}

// Kill signals the group. Callers Close the guard once the process is reaped;
// after that the pid (and its group id) may belong to an unrelated process,
// so Kill becomes a no-op.
func (g *ProcessGuard) Kill() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	_ = syscall.Kill(-g.proc.Pid, syscall.SIGKILL)
	_ = g.proc.Kill()
}

func (g *ProcessGuard) Close() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
}
