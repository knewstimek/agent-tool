//go:build windows

package prockill

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"agent-tool/common"

	"golang.org/x/sys/windows"
)

var (
	ntdll                  = syscall.NewLazyDLL("ntdll.dll")
	procNtSuspendProcess   = ntdll.NewProc("NtSuspendProcess")
	procNtResumeProcess    = ntdll.NewProc("NtResumeProcess")
)

// processDetails holds info about a single process for display.
type processDetails struct {
	PID     int
	PPID    int
	Name    string
	MemKB   uint64
	CmdLine string
	State   byte // unused on Windows
}

// getProcessDetails returns details for a specific PID using CreateToolhelp32Snapshot.
func getProcessDetails(pid int) (*processDetails, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, err
	}

	for {
		if int(entry.ProcessID) == pid {
			return &processDetails{
				PID:  pid,
				PPID: int(entry.ParentProcessID),
				Name: windows.UTF16ToString(entry.ExeFile[:]),
			}, nil
		}
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	return nil, fmt.Errorf("process %d not found", pid)
}

// getDescendants returns all descendant PIDs (recursive) of the given PID.
// Returns PIDs in BFS order (parent first, children after).
func getDescendants(pid int) []int {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	// Build PPID → children map
	childMap := make(map[int][]int)
	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil
	}
	for {
		p := int(entry.ProcessID)
		pp := int(entry.ParentProcessID)
		if p != 0 {
			childMap[pp] = append(childMap[pp], p)
		}
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	// BFS from pid
	var result []int
	queue := []int{pid}
	visited := map[int]bool{pid: true}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		result = append(result, current)

		for _, child := range childMap[current] {
			if !visited[child] {
				visited[child] = true
				queue = append(queue, child)
			}
		}
	}

	return result
}

// killSingle kills a single process by PID.
func killSingle(pid int, signal string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "taskkill", "/PID", strconv.Itoa(pid), "/F")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(common.DecodeConsoleOutput(out)))
	}
	return nil
}

// killTreePlatform kills a process and all its descendants using taskkill /T.
func killTreePlatform(pid int, signal string) (killed []int, failed map[int]error) {
	failed = make(map[int]error)

	// Get descendants before killing (for reporting)
	descendants := getDescendants(pid)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "taskkill", "/PID", strconv.Itoa(pid), "/T", "/F")
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(common.DecodeConsoleOutput(out))

	if err != nil {
		// Parse output to determine which PIDs succeeded/failed
		for _, desc := range descendants {
			pidStr := strconv.Itoa(desc)
			if strings.Contains(output, pidStr) && strings.Contains(output, "SUCCESS") {
				killed = append(killed, desc)
			} else {
				failed[desc] = fmt.Errorf("%s", output)
			}
		}
		// If no parsing worked, report all as killed attempt
		if len(killed) == 0 && len(failed) == 0 {
			failed[pid] = fmt.Errorf("%s", output)
		}
		return
	}

	// Success — all descendants killed
	killed = descendants
	return
}

// handleZombies is a no-op on Windows (no zombie process concept).
func handleZombies(_ int) string {
	return ""
}

// suspendProcess suspends a process using NtSuspendProcess.
func suspendProcess(pid int) error {
	handle, err := windows.OpenProcess(windows.PROCESS_SUSPEND_RESUME, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	r, _, err := procNtSuspendProcess.Call(uintptr(handle))
	if r != 0 {
		return fmt.Errorf("NtSuspendProcess(%d): NTSTATUS 0x%X: %v", pid, r, err)
	}
	return nil
}

// resumeProcess resumes a process using NtResumeProcess.
func resumeProcess(pid int) error {
	handle, err := windows.OpenProcess(windows.PROCESS_SUSPEND_RESUME, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	r, _, err := procNtResumeProcess.Call(uintptr(handle))
	if r != 0 {
		return fmt.Errorf("NtResumeProcess(%d): NTSTATUS 0x%X: %v", pid, r, err)
	}
	return nil
}
