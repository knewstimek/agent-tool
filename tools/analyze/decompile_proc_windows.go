//go:build windows

package analyze

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// prepareWorker sets Windows process attributes. The worker is then confined
// with common.GuardProcess(KillOnClose): if the server exits by any path --
// including being killed -- the kernel kills the worker, so no orphan
// survives, and the job memory limit backs up the worker's heap watchdog.
func prepareWorker(cmd *exec.Cmd) {
	// The MCP server usually has no console; without CREATE_NO_WINDOW every
	// worker would flash a console window.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}
