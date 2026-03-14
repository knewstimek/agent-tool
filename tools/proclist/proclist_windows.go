//go:build windows

package proclist

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"agent-tool/common"

	"golang.org/x/sys/windows"
)

// ProcessInfo represents process information.
type ProcessInfo struct {
	PID     int
	Name    string
	CmdLine string
	MemKB   uint64 // in KB
}

// PortEntry represents a port-to-PID mapping.
type PortEntry struct {
	PID      int
	Port     int
	Protocol string
	State    string
}

// listProcesses returns a list of running processes on Windows.
func listProcesses() ([]ProcessInfo, error) {
	// Collect PID+name via CreateToolhelp32Snapshot (very fast)
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var procs []ProcessInfo

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, err
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		procs = append(procs, ProcessInfo{
			PID:  int(entry.ProcessID),
			Name: name,
		})
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	// Enrich with memory info via tasklist /FO CSV (fast, ~1 second)
	enrichWithTasklist(procs)

	return procs, nil
}

// enrichWithTasklist enriches process info with memory data from tasklist.
func enrichWithTasklist(procs []ProcessInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "tasklist", "/FO", "CSV", "/NH")
	out, err := cmd.Output()
	if err != nil {
		return
	}

	pidMap := make(map[int]int, len(procs))
	for i := range procs {
		pidMap[procs[i].PID] = i
	}

	reader := csv.NewReader(strings.NewReader(common.DecodeConsoleOutput(out)))
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1

	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		// "Image Name","PID","Session Name","Session#","Mem Usage"
		if len(record) < 5 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(record[1]))
		if err != nil {
			continue
		}
		idx, ok := pidMap[pid]
		if !ok {
			continue
		}
		// Memory: "123,456 K" format
		memStr := strings.ReplaceAll(record[4], ",", "")
		memStr = strings.ReplaceAll(memStr, " K", "")
		memStr = strings.TrimSpace(memStr)
		memKB, _ := strconv.ParseUint(memStr, 10, 64)
		procs[idx].MemKB = memKB
	}
}

// enrichCommandLines queries command lines via wmic only for filtered processes.
// Calling wmic for all processes is too slow, so it is applied only to filtered results.
func enrichCommandLines(procs []ProcessInfo) {
	if len(procs) == 0 || len(procs) > 50 {
		return // skip if more than 50 (wmic itself is slow with too many)
	}

	// Call wmic with PID list
	var pidConds []string
	for _, p := range procs {
		pidConds = append(pidConds, fmt.Sprintf("ProcessId=%d", p.PID))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	where := strings.Join(pidConds, " or ")
	cmd := exec.CommandContext(ctx, "wmic", "process", "where", where, "get", "ProcessId,CommandLine", "/FORMAT:CSV")
	out, err := cmd.Output()
	if err != nil {
		return
	}

	pidMap := make(map[int]int, len(procs))
	for i := range procs {
		pidMap[procs[i].PID] = i
	}

	reader := csv.NewReader(strings.NewReader(common.DecodeConsoleOutput(out)))
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return
	}

	// Find header
	var cmdIdx, pidIdx int = -1, -1
	for i, rec := range records {
		if len(rec) < 2 {
			continue
		}
		for j, col := range rec {
			switch strings.ToLower(strings.TrimSpace(col)) {
			case "commandline":
				cmdIdx = j
			case "processid":
				pidIdx = j
			}
		}
		if cmdIdx >= 0 && pidIdx >= 0 {
			for _, rec := range records[i+1:] {
				if pidIdx >= len(rec) {
					continue
				}
				pid, err := strconv.Atoi(strings.TrimSpace(rec[pidIdx]))
				if err != nil {
					continue
				}
				if idx, ok := pidMap[pid]; ok && cmdIdx < len(rec) {
					procs[idx].CmdLine = strings.TrimSpace(rec[cmdIdx])
				}
			}
			break
		}
	}
}

// ListPortPIDs returns port-to-PID mappings using netstat -ano on Windows.
func ListPortPIDs() ([]PortEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "netstat", "-ano")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var entries []PortEntry
	scanner := bufio.NewScanner(strings.NewReader(common.DecodeConsoleOutput(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		proto := strings.ToUpper(fields[0])
		if proto != "TCP" && proto != "UDP" {
			continue
		}

		// Extract port from local address
		localAddr := fields[1]
		lastColon := strings.LastIndex(localAddr, ":")
		if lastColon < 0 {
			continue
		}
		port, err := strconv.Atoi(localAddr[lastColon+1:])
		if err != nil {
			continue
		}

		var state string
		var pidStr string
		if proto == "TCP" && len(fields) >= 5 {
			state = fields[3]
			pidStr = fields[4]
		} else if proto == "UDP" && len(fields) >= 4 {
			state = ""
			if len(fields) >= 5 {
				pidStr = fields[4]
			} else {
				pidStr = fields[3]
			}
		} else {
			continue
		}

		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		entries = append(entries, PortEntry{
			PID:      pid,
			Port:     port,
			Protocol: proto,
			State:    state,
		})
	}

	return entries, nil
}
