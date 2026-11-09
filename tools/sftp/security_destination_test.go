package sftp

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDownloadDestinationProtectsCaseAndLinks(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, ".ssh")
	if err := os.Mkdir(protected, 0700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if err := os.WriteFile(filepath.Join(root, ".env"), []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, suffix := range []string{".SSH/new.txt", ".ssh./new.txt", "KNOWN_HOSTS", ".ENV", ".ENV::$DATA"} {
			if err := isSensitiveLocalPath(filepath.Join(root, filepath.FromSlash(suffix))); err == nil {
				t.Errorf("Windows spelling bypassed sensitive destination check: %s", suffix)
			}
		}
	}
	link := filepath.Join(root, "ordinary")
	if err := os.Symlink(protected, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	for _, suffix := range []string{"new.txt", "new/child.txt"} {
		if err := isSensitiveLocalPath(filepath.Join(link, filepath.FromSlash(suffix))); err == nil {
			t.Errorf("symlink ancestor bypassed sensitive destination check: %s", suffix)
		}
	}
	final := filepath.Join(root, "ordinary-file")
	if err := os.Symlink(filepath.Join(protected, "new-file"), final); err != nil {
		t.Fatal(err)
	}
	if err := isSensitiveLocalPath(final); err == nil {
		t.Fatal("dangling final symlink bypassed sensitive destination check")
	}
	if err := isSensitiveLocalPath(filepath.Join(root, "safe", "new.txt")); err != nil {
		t.Fatalf("ordinary new destination rejected: %v", err)
	}
}
