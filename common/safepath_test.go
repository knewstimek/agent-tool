package common

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDangerousPathIncludesProtectedDirectoryItself(t *testing.T) {
	roots := []string{"/etc", "/boot", "/usr/lib", "/root"}
	if runtime.GOOS == "windows" {
		// Only inspect strings; never operate on the actual system directory.
		root := filepath.Join(t.TempDir(), "Windows")
		t.Setenv("WINDIR", root)
		roots = []string{root}
	}
	for _, root := range roots {
		for _, path := range []string{root, root + string(os.PathSeparator), filepath.Join(root, "child")} {
			if err := CheckDangerousPath(path); err == nil {
				t.Errorf("protected path accepted: %s", path)
			}
		}
		if err := CheckDangerousPath(root + "-backup"); err != nil {
			t.Errorf("sibling was blocked: %v", err)
		}
	}
}
