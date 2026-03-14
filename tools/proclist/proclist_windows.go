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

// ProcessInfo는 프로세스 정보이다.
type ProcessInfo struct {
	PID     int
	Name    string
	CmdLine string
	MemKB   uint64 // KB 단위
}

// PortEntry는 포트-PID 매핑이다.
type PortEntry struct {
	PID      int
	Port     int
	Protocol string
	State    string
}

// listProcesses는 Windows에서 실행 중인 프로세스 목록을 반환한다.
func listProcesses() ([]ProcessInfo, error) {
	// CreateToolhelp32Snapshot으로 PID+이름 수집 (매우 빠름)
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

	// tasklist /FO CSV로 메모리 정보 보강 (빠름, ~1초)
	enrichWithTasklist(procs)

	return procs, nil
}

// enrichWithTasklist는 tasklist로 메모리 정보를 보강한다.
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
		// 메모리: "123,456 K" 형식
		memStr := strings.ReplaceAll(record[4], ",", "")
		memStr = strings.ReplaceAll(memStr, " K", "")
		memStr = strings.TrimSpace(memStr)
		memKB, _ := strconv.ParseUint(memStr, 10, 64)
		procs[idx].MemKB = memKB
	}
}

// enrichCommandLines는 필터된 프로세스에 대해서만 wmic로 커맨드라인을 조회한다.
// 전체 프로세스에 대해 wmic를 호출하면 너무 느리므로, 필터된 결과에만 적용.
func enrichCommandLines(procs []ProcessInfo) {
	if len(procs) == 0 || len(procs) > 50 {
		return // 50개 초과면 skip (너무 많으면 wmic 자체가 느림)
	}

	// PID 목록으로 wmic 호출
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

	// 헤더 찾기
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

// listPortPIDs는 Windows에서 netstat -ano로 포트-PID 매핑을 반환한다.
func listPortPIDs() ([]PortEntry, error) {
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

		// 로컬 주소에서 포트 추출
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
