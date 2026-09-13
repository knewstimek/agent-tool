package delete

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-tool/common"
)

func TestHandleDeletesFileWithoutRecursive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, out, err := Handle(t.Context(), nil, DeleteInput{FilePath: path})
	if err != nil || result.IsError {
		t.Fatalf("Handle() failed: result=%+v out=%q err=%v", result, out.Result, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still exists after delete: %v", err)
	}
}

func TestHandleDirectoryRequiresRecursiveWithGuidance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tree")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	result, out, err := Handle(t.Context(), nil, DeleteInput{FilePath: path})
	if err != nil || !result.IsError {
		t.Fatalf("Handle() should reject directory without recursive: result=%+v err=%v", result, err)
	}
	if !strings.Contains(out.Result, "recursive=true") || !strings.Contains(out.Result, "dry_run=true") {
		t.Fatalf("error does not explain how to proceed: %q", out.Result)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("rejected directory was modified: %v", err)
	}
}

func TestHandleRecursiveDryRunReportsImpact(t *testing.T) {
	path := makeTree(t)

	result, out, err := Handle(t.Context(), nil, DeleteInput{FilePath: path, Recursive: true, DryRun: true})
	if err != nil || result.IsError {
		t.Fatalf("Handle() dry run failed: result=%+v out=%q err=%v", result, out.Result, err)
	}
	for _, want := range []string{"[DRY RUN]", "2 files", "2 directories", "9 bytes"} {
		if !strings.Contains(out.Result, want) {
			t.Fatalf("dry-run output %q does not contain %q", out.Result, want)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("dry run modified directory: %v", err)
	}
}

func TestHandleRecursivelyDeletesDirectory(t *testing.T) {
	path := makeTree(t)

	result, out, err := Handle(t.Context(), nil, DeleteInput{FilePath: path, Recursive: "true"})
	if err != nil || result.IsError {
		t.Fatalf("Handle() failed: result=%+v out=%q err=%v", result, out.Result, err)
	}
	if !strings.Contains(out.Result, "2 files, 2 directories, 9 bytes") {
		t.Fatalf("unexpected result: %q", out.Result)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("directory still exists after recursive delete: %v", err)
	}
}

func TestHandleRejectsWorkspaceRoot(t *testing.T) {
	old := common.GetWorkspace()
	t.Cleanup(func() { common.SetWorkspace(old) })
	workspace := t.TempDir()
	common.SetWorkspace(workspace)

	result, out, err := Handle(t.Context(), nil, DeleteInput{FilePath: workspace, Recursive: true})
	if err != nil || !result.IsError {
		t.Fatalf("Handle() should reject workspace root: result=%+v err=%v", result, err)
	}
	if !strings.Contains(out.Result, "workspace") || !strings.Contains(out.Result, "choose a child directory") {
		t.Fatalf("error does not explain the protected path: %q", out.Result)
	}
}

func TestPlanDirectoryDeleteRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}

	_, err := planDirectoryDelete(root)
	if err == nil || !strings.Contains(err.Error(), "symbolic link found") {
		t.Fatalf("expected actionable symlink error, got %v", err)
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil || string(data) != "keep" {
		t.Fatalf("symlink target was modified: data=%q err=%v", data, readErr)
	}
}

func makeTree(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "tree")
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("1234"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b.txt"), []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}
