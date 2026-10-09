//go:build !windows

package analyze

import (
	"os"
	"os/exec"
	"syscall"
)

func prepareWorker(cmd *exec.Cmd) {
	// Own process group so kill reaches anything the worker might start.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	setParentDeathSignal(cmd.SysProcAttr)
}

// workerGuard kills the worker's process group. Unix has no portable
// kill-on-parent-exit; Linux uses the parent-death signal, and everywhere the
// worker also watches its parent and enforces its own heap limit.
type workerGuard struct{ proc *os.Process }

func guardWorker(p *os.Process, memLimit uint64) (*workerGuard, error) {
	return &workerGuard{proc: p}, nil
}

// kill is only called before the worker is reaped: after Wait the pid (and
// its group id) may already belong to an unrelated process.
func (g *workerGuard) kill() {
	syscall.Kill(-g.proc.Pid, syscall.SIGKILL)
	g.proc.Kill()
}

// close has nothing to release: the caller has already reaped the worker, and
// the worker starts no processes of its own.
func (g *workerGuard) close() {}
