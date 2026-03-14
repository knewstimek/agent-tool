//go:build !windows

package sysinfo

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func getMemoryInfo() (total, available uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var memTotal, memAvail uint64
	found := 0
	for scanner.Scan() && found < 2 {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			memTotal = parseMemInfoLine(line)
			found++
		} else if strings.HasPrefix(line, "MemAvailable:") {
			memAvail = parseMemInfoLine(line)
			found++
		}
	}
	if found < 2 {
		return 0, 0, fmt.Errorf("cannot parse /proc/meminfo")
	}
	return memTotal * 1024, memAvail * 1024, nil // kB → bytes
}

func parseMemInfoLine(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		return v
	}
	return 0
}

func getDiskInfo() ([]DiskInfo, error) {
	var disks []DiskInfo
	paths := []string{"/"}

	// Check common mount points
	for _, p := range []string{"/home", "/tmp", "/var"} {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, p)
		}
	}

	seen := make(map[uint64]bool)
	for _, p := range paths {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(p, &stat); err != nil {
			continue
		}
		// Prevent duplicate filesystems (Blocks+Bsize combination — Fsid field name varies by OS)
		fsid := uint64(stat.Blocks)<<32 | uint64(stat.Bsize)
		if seen[fsid] {
			continue
		}
		seen[fsid] = true

		total := uint64(stat.Blocks) * uint64(stat.Bsize)
		free := uint64(stat.Bavail) * uint64(stat.Bsize)
		if total > 0 {
			disks = append(disks, DiskInfo{
				Path:  p,
				Total: total,
				Free:  free,
			})
		}
	}
	return disks, nil
}

func measureCPU(duration time.Duration) (float64, error) {
	idle1, total1, err := readCPUStat()
	if err != nil {
		return 0, err
	}

	time.Sleep(duration)

	idle2, total2, err := readCPUStat()
	if err != nil {
		return 0, err
	}

	totalDelta := float64(total2 - total1)
	idleDelta := float64(idle2 - idle1)
	if totalDelta == 0 {
		return 0, nil
	}

	return (1 - idleDelta/totalDelta) * 100, nil
}

func readCPUStat() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return 0, 0, fmt.Errorf("unexpected /proc/stat format")
			}
			var sum uint64
			for _, field := range fields[1:] {
				v, _ := strconv.ParseUint(field, 10, 64)
				sum += v
			}
			idleVal, _ := strconv.ParseUint(fields[4], 10, 64)
			return idleVal, sum, nil
		}
	}
	return 0, 0, fmt.Errorf("/proc/stat: cpu line not found")
}

func getUptime() (time.Duration, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("cannot parse /proc/uptime")
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(secs * float64(time.Second)), nil
}

func getHostnameOS() (string, error) {
	return os.Hostname()
}

func getLocale() string {
	for _, key := range []string{"LANG", "LC_ALL", "LANGUAGE", "LC_CTYPE"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return ""
}
