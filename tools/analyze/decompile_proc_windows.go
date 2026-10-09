//go:build windows

package analyze

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func prepareWorker(cmd *exec.Cmd) {
	// The MCP server usually has no console; without CREATE_NO_WINDOW every
	// worker would flash a console window.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

// workerGuard confines a started worker in its own job object.
// KILL_ON_JOB_CLOSE ties the worker's life to the job handle this process
// holds: if the server exits by any path -- including being killed, when no
// cleanup code runs -- the kernel closes the handle and kills the worker, so
// no orphan survives. The process memory limit is the hard backstop behind
// the worker's own heap watchdog.
type workerGuard struct {
	job  windows.Handle
	proc *os.Process
}

func guardWorker(p *os.Process, memLimit uint64) (*workerGuard, error) {
	g := &workerGuard{proc: p}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return g, fmt.Errorf("CreateJobObject: %w", err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
		windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
	info.ProcessMemoryLimit = uintptr(memLimit)
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return g, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		windows.CloseHandle(job)
		return g, fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(h)
	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		windows.CloseHandle(job)
		return g, fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	g.job = job
	return g, nil
}

// kill stops the worker now.
func (g *workerGuard) kill() {
	if g.job != 0 {
		windows.TerminateJobObject(g.job, 1)
		return
	}
	g.proc.Kill()
}

// close releases the job; with KILL_ON_JOB_CLOSE anything still in it dies.
func (g *workerGuard) close() {
	if g.job != 0 {
		windows.CloseHandle(g.job)
		g.job = 0
	}
}
