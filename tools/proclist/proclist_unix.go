//go:build !windows

package proclist

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// listProcesses reads /proc on Linux and returns a list of processes.
func listProcesses() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("cannot read /proc: %w", err)
	}

	var procs []ProcessInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		info := ProcessInfo{PID: pid}

		// Process name (comm)
		if data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm")); err == nil {
			info.Name = strings.TrimSpace(string(data))
		}

		// Command line (limited to 4KB — ARG_MAX can be several MB, so limit to save memory)
		if f, err := os.Open(filepath.Join("/proc", entry.Name(), "cmdline")); err == nil {
			buf := make([]byte, 4096)
			n, _ := f.Read(buf)
			f.Close()
			if n > 0 {
				info.CmdLine = strings.Join(strings.Split(strings.TrimRight(string(buf[:n]), "\x00"), "\x00"), " ")
			}
		}

		// Memory (VmRSS from status)
		if f, err := os.Open(filepath.Join("/proc", entry.Name(), "status")); err == nil {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "VmRSS:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						info.MemKB, _ = strconv.ParseUint(fields[1], 10, 64)
					}
					break
				}
			}
			f.Close()
		}

		procs = append(procs, info)
	}

	return procs, nil
}

// ListPortPIDs reads /proc/net/tcp{,6} on Linux and returns port-to-PID mappings.
func ListPortPIDs() ([]PortEntry, error) {
	// Build inode → PortEntry mapping
	inodeMap := make(map[uint64]PortEntry)

	for _, proto := range []struct {
		file string
		name string
	}{
		{"/proc/net/tcp", "TCP"},
		{"/proc/net/tcp6", "TCP"},
		{"/proc/net/udp", "UDP"},
		{"/proc/net/udp6", "UDP"},
	} {
		f, err := os.Open(proto.file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		if !scanner.Scan() { // skip header
			f.Close()
			continue
		}
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			// local_address (fields[1]) = hex_ip:hex_port
			addrParts := strings.Split(fields[1], ":")
			if len(addrParts) != 2 {
				continue
			}
			port64, err := strconv.ParseUint(addrParts[1], 16, 32)
			if err != nil {
				continue
			}

			// state (fields[3])
			stateHex, _ := strconv.ParseUint(fields[3], 16, 8)
			state := tcpStateStr(int(stateHex))

			// inode (fields[9])
			inode, err := strconv.ParseUint(fields[9], 10, 64)
			if err != nil || inode == 0 {
				continue
			}

			inodeMap[inode] = PortEntry{
				Port:     int(port64),
				Protocol: proto.name,
				State:    state,
			}
		}
		f.Close()
	}

	if len(inodeMap) == 0 {
		return nil, nil
	}

	// Traverse /proc/[pid]/fd/ to map inode → PID
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var result []PortEntry
	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// "socket:[12345]"
			if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
				continue
			}
			inodeStr := link[8 : len(link)-1]
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}
			if pe, ok := inodeMap[inode]; ok {
				pe.PID = pid
				result = append(result, pe)
				delete(inodeMap, inode) // match only once
			}
		}
	}

	return result, nil
}

// enrichCommandLines is a no-op on Linux (cmdline is already read from /proc).
func enrichCommandLines(_ []ProcessInfo) {}

func tcpStateStr(state int) string {
	switch state {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSE"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	default:
		return fmt.Sprintf("0x%02X", state)
	}
}
