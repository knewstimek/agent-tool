//go:build !windows

package prockill

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// processDetails holds info about a single process for display.
type processDetails struct {
	PID     int
	PPID    int
	Name    string
	MemKB   uint64
	CmdLine string
	State   byte // 'Z' for zombie, 'S' for sleeping, 'R' for running, etc.
}

// getProcessDetails returns details for a specific PID from /proc.
func getProcessDetails(pid int) (*processDetails, error) {
	procDir := filepath.Join("/proc", strconv.Itoa(pid))
	if _, err := os.Stat(procDir); err != nil {
		return nil, fmt.Errorf("process %d not found", pid)
	}

	d := &processDetails{PID: pid}

	// Name from /proc/[pid]/comm
	if data, err := os.ReadFile(filepath.Join(procDir, "comm")); err == nil {
		d.Name = strings.TrimSpace(string(data))
	}

	// PPID and state from /proc/[pid]/stat
	// Format: pid (comm) state ppid ...
	if data, err := os.ReadFile(filepath.Join(procDir, "stat")); err == nil {
		s := string(data)
		// Find the closing paren of comm (which may contain spaces/parens)
		closeIdx := strings.LastIndex(s, ")")
		if closeIdx > 0 && closeIdx+2 < len(s) {
			fields := strings.Fields(s[closeIdx+2:])
			if len(fields) >= 2 {
				if len(fields[0]) > 0 {
					d.State = fields[0][0]
				}
				d.PPID, _ = strconv.Atoi(fields[1])
			}
		}
	}

	// Command line from /proc/[pid]/cmdline
	if f, err := os.Open(filepath.Join(procDir, "cmdline")); err == nil {
		buf := make([]byte, 4096)
		n, _ := f.Read(buf)
		f.Close()
		if n > 0 {
			d.CmdLine = strings.Join(strings.Split(strings.TrimRight(string(buf[:n]), "\x00"), "\x00"), " ")
		}
	}

	// Memory (VmRSS) from /proc/[pid]/status
	if f, err := os.Open(filepath.Join(procDir, "status")); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					d.MemKB, _ = strconv.ParseUint(fields[1], 10, 64)
				}
				break
			}
		}
		f.Close()
	}

	return d, nil
}

// getDescendants returns all descendant PIDs (recursive) of the given PID.
// Returns PIDs in BFS order (parent first, children after).
func getDescendants(pid int) []int {
	// Build PPID → children map from all processes
	childMap := make(map[int][]int)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []int{pid}
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		cpid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		// Read PPID from /proc/[pid]/stat
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		s := string(data)
		closeIdx := strings.LastIndex(s, ")")
		if closeIdx <= 0 || closeIdx+2 >= len(s) {
			continue
		}
		fields := strings.Fields(s[closeIdx+2:])
		if len(fields) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		childMap[ppid] = append(childMap[ppid], cpid)
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

// killSingle kills a single process with the given signal.
func killSingle(pid int, signal string) error {
	sig := parseSignal(signal)
	err := syscall.Kill(pid, sig)
	if err != nil {
		return fmt.Errorf("kill(%d, %s): %w", pid, signal, err)
	}
	return nil
}

// killTreePlatform kills a process and all its descendants.
// Kills in reverse order (leaves first) to prevent orphaning.
func killTreePlatform(pid int, signal string) (killed []int, failed map[int]error) {
	failed = make(map[int]error)
	descendants := getDescendants(pid)
	myPID := os.Getpid()

	// Kill in reverse (leaves first, root last)
	for i := len(descendants) - 1; i >= 0; i-- {
		target := descendants[i]
		if target <= 1 || target == myPID {
			continue
		}
		if err := killSingle(target, signal); err != nil {
			failed[target] = err
		} else {
			killed = append(killed, target)
		}
	}

	return
}

// handleZombies checks for zombie processes among the target and its descendants.
// For each zombie found, sends SIGCHLD to its parent to trigger reaping.
func handleZombies(pid int) string {
	descendants := getDescendants(pid)
	var sb strings.Builder

	for _, dpid := range descendants {
		details, err := getProcessDetails(dpid)
		if err != nil {
			continue
		}
		if details.State != 'Z' {
			continue
		}

		sb.WriteString(fmt.Sprintf("  Zombie PID %d (%s), parent PID %d", dpid, details.Name, details.PPID))

		if details.PPID > 1 {
			// Send SIGCHLD to parent to trigger waitpid/reap
			err := syscall.Kill(details.PPID, syscall.SIGCHLD)
			if err != nil {
				sb.WriteString(fmt.Sprintf(" — SIGCHLD to parent failed: %v\n", err))
			} else {
				sb.WriteString(" — sent SIGCHLD to parent for reaping\n")
			}
		} else {
			sb.WriteString(" — parent is init/systemd, will auto-reap\n")
		}
	}

	return sb.String()
}

// parseSignal converts a signal name to syscall.Signal.
func parseSignal(name string) syscall.Signal {
	switch strings.ToLower(name) {
	case "term":
		return syscall.SIGTERM
	case "hup":
		return syscall.SIGHUP
	case "int":
		return syscall.SIGINT
	case "stop":
		return syscall.SIGSTOP
	case "cont":
		return syscall.SIGCONT
	default: // "kill"
		return syscall.SIGKILL
	}
}

// suspendProcess sends SIGSTOP to a process.
func suspendProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGSTOP)
}

// resumeProcess sends SIGCONT to a process.
func resumeProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGCONT)
}
