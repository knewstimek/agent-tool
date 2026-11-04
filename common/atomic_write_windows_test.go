//go:build windows

package common

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestReadonlyWriteFailureDoesNotLeakStagedFile(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "readonly.txt")
	if err := os.WriteFile(p, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		entries, _ := os.ReadDir(d)
		for _, entry := range entries {
			os.Chmod(filepath.Join(d, entry.Name()), 0600)
		}
	})
	if err := os.Chmod(p, 0444); err != nil {
		t.Fatal(err)
	}
	_, info, err := ReadFileWithEncodingHash(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFileWithEncoding(p, "changed", info); err == nil {
		t.Fatal("read-only replacement should fail")
	}
	raw, _ := os.ReadFile(p)
	if string(raw) != "original" {
		t.Fatal("read-only original changed")
	}
	leftovers, _ := filepath.Glob(filepath.Join(d, ".agent-tool-*.tmp"))
	if len(leftovers) != 0 {
		t.Fatalf("staged read-only temporary files leaked: %d", len(leftovers))
	}
}

func TestAtomicWriteDoesNotRewriteDeleteLockedOriginal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "locked.txt")
	original := []byte("original")
	if err := os.WriteFile(p, original, 0600); err != nil {
		t.Fatal(err)
	}
	path, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	_, info, err := ReadFileWithEncodingHash(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFileWithEncoding(p, "changed", info); err == nil {
		t.Fatal("replacement should fail while the original denies delete sharing")
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "original" {
		t.Fatalf("failed atomic replacement modified original: %q %v", got, err)
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(p), ".agent-tool-*.tmp"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary files leaked: %v %v", leftovers, err)
	}
}
