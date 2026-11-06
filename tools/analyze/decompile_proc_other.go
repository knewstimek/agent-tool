//go:build !windows

package analyze

import (
	"os/exec"
	"syscall"
)

// prepareWorker puts the worker in its own process group so
// common.ProcessGuard.Kill reaches anything it might start. Unix has no
// portable kill-on-parent-exit; Linux adds the parent-death signal, and
// everywhere the worker also watches its parent and enforces its own heap limit.
func prepareWorker(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	setParentDeathSignal(cmd.SysProcAttr)
}
