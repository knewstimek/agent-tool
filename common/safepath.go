package common

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// CheckDangerousPath blocks operations on critical system paths.
// Shared by delete, rename, mkdir, and other file management tools
// to prevent accidental or malicious modification of system files.
func CheckDangerousPath(cleaned string) error {
	normalized := strings.ToLower(filepath.ToSlash(cleaned))

	var blocked []string
	if runtime.GOOS == "windows" {
		winDir := os.Getenv("WINDIR")
		if winDir == "" {
			winDir = `C:\Windows`
		}
		blocked = []string{
			strings.ToLower(filepath.ToSlash(winDir)) + "/",
		}
	} else {
		blocked = []string{
			"/etc/", "/boot/", "/sbin/", "/usr/sbin/",
			"/proc/", "/sys/", "/dev/",
			"/var/run/", "/run/",
			"/usr/lib/systemd/", "/lib/systemd/",
			"/usr/lib64/", "/lib64/",
			"/lib/", "/usr/lib/",
			"/root/",
		}
	}

	for _, prefix := range blocked {
		if strings.HasPrefix(normalized, prefix) {
			return fmt.Errorf("operation on system path is not allowed: %s", cleaned)
		}
	}
	return nil
}

// CheckWindowsReserved blocks Windows reserved device names and ADS paths.
func CheckWindowsReserved(cleaned string) error {
	if runtime.GOOS != "windows" {
		return nil
	}

	// Block ADS (Alternate Data Stream)
	drive := filepath.VolumeName(cleaned)
	rest := cleaned[len(drive):]
	if strings.Contains(rest, ":") {
		return fmt.Errorf("alternate data stream (ADS) paths are not allowed")
	}

	// Block reserved device names
	base := filepath.Base(cleaned)
	upperBase := strings.ToUpper(strings.TrimSuffix(base, filepath.Ext(base)))
	reserved := []string{
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
	}
	for _, r := range reserved {
		if upperBase == r {
			return fmt.Errorf("operation on Windows reserved device name is not allowed: %s", base)
		}
	}
	return nil
}
