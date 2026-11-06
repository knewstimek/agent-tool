//go:build windows

package common

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessGuard confines a started process and everything it spawns in a job
// object. Job membership is inherited by children and survives the death of
// an intermediate parent, so Kill reaches grandchildren that taskkill /T
// (which walks parent PIDs) misses once their parent has exited.
//
// The process is assigned right after Start, so a child created in that
// instant could escape; callers launch ordinary commands, not fork bombs.
type ProcessGuard struct {
	mu     sync.Mutex
	job    windows.Handle
	proc   *os.Process
	closed bool
}

type GuardOptions struct {
	// KillOnClose ties the tree's life to this process: when agent-tool exits
	// by any path (even killed), the kernel closes the handle and kills the
	// tree. Use for helpers (decompile workers), not for user processes meant
	// to outlive the server (procexec background servers).
	KillOnClose bool
	// MemoryLimit caps per-process committed memory in bytes; 0 = no limit.
	MemoryLimit uint64
}

// GuardProcess always returns a usable guard; on error it falls back to
// killing by PID tree, and the error says why the job object is missing.
func GuardProcess(p *os.Process, opts GuardOptions) (*ProcessGuard, error) {
	g := &ProcessGuard{proc: p}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return g, fmt.Errorf("CreateJobObject: %w", err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if opts.KillOnClose {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
			windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
	}
	if opts.MemoryLimit > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
		info.ProcessMemoryLimit = uintptr(opts.MemoryLimit)
	}
	if info.BasicLimitInformation.LimitFlags != 0 {
		if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			windows.CloseHandle(job)
			return g, fmt.Errorf("SetInformationJobObject: %w", err)
		}
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

// Kill terminates the whole tree now. Without a job object it falls back to
// taskkill /T, then to killing the root process alone.
//
// After Close, Kill does nothing: callers close once the process is reaped,
// and the taskkill fallback works by PID, which by then may belong to an
// unrelated process tree.
func (g *ProcessGuard) Kill() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	if g.job != 0 {
		windows.TerminateJobObject(g.job, 1)
		return
	}
	tk := exec.Command("taskkill", "/PID", strconv.Itoa(g.proc.Pid), "/T", "/F")
	tk.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if tk.Run() != nil {
		g.proc.Kill()
	}
}

// Close releases the job handle. With KillOnClose anything still in the job
// dies; without it, survivors keep running untracked.
func (g *ProcessGuard) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	if g.job != 0 {
		windows.CloseHandle(g.job)
		g.job = 0
	}
}
