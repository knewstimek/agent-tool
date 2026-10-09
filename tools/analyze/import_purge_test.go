package analyze

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Argument sizes of stdcall imports come from the installed 32-bit DLLs,
// through forwarders (kernel32 -> api-ms-win-core-* -> kernelbase) and API
// set names. Windows only: other hosts have no system DLLs to read.
func TestImportPurgeFromSystemDLLs(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("needs the Windows system DLLs")
	}
	root := os.Getenv("SystemRoot")
	if _, err := os.Stat(filepath.Join(root, "SysWOW64", "kernel32.dll")); err != nil {
		t.Skip("no 32-bit system DLLs")
	}
	for _, c := range []struct {
		dll, fn string
		want    int
	}{
		{"kernel32.dll", "CreateFileA", 28}, // forwards into kernelbase
		{"kernel32.dll", "GetTickCount", 0},
		{"user32.dll", "MessageBoxA", 16},
		{"advapi32.dll", "RegOpenKeyExA", 20},
		{"api-ms-win-core-synch-l1-2-0.dll", "Sleep", 4},
		{"msvcrt.dll", "printf", 0}, // cdecl
		{"no-such-library.dll", "Anything", 0},
	} {
		if got := dllPurge("", c.dll, c.fn, 0, 0); got != c.want {
			t.Errorf("%s!%s pops %d, want %d", c.dll, c.fn, got, c.want)
		}
	}
}
