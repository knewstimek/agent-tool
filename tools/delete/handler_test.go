package delete

import (
	"fmt"
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

func TestHandleBatchDeletesAndAggregates(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first.txt")
	second := filepath.Join(root, "second.txt")
	tree := filepath.Join(root, "tree")
	if err := os.WriteFile(first, []byte("1234"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "nested.txt"), []byte("123456"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, out, err := Handle(t.Context(), nil, DeleteInput{
		FilePaths: []string{first, second, tree},
		Recursive: true,
	})
	if err != nil || result.IsError {
		t.Fatalf("Handle() batch failed: result=%+v out=%q err=%v", result, out.Result, err)
	}
	for _, want := range []string{"deleted 3/3 targets", "3 files", "1 directories", "15 bytes", "0 errors"} {
		if !strings.Contains(out.Result, want) {
			t.Fatalf("batch output %q does not contain %q", out.Result, want)
		}
	}
	for _, path := range []string{first, second, tree} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("batch target still exists: %s (%v)", path, err)
		}
	}
}

func TestHandleBatchDryRunDoesNotModifyTargets(t *testing.T) {
	root := t.TempDir()
	paths := []string{filepath.Join(root, "a.txt"), filepath.Join(root, "b.txt")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	result, out, err := Handle(t.Context(), nil, DeleteInput{FilePaths: paths, DryRun: true})
	if err != nil || result.IsError {
		t.Fatalf("Handle() batch dry run failed: result=%+v out=%q err=%v", result, out.Result, err)
	}
	if !strings.Contains(out.Result, "[DRY RUN] 2/2 targets passed validation") {
		t.Fatalf("unexpected dry-run result: %q", out.Result)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("dry run modified %s: %v", path, err)
		}
	}
}

func TestHandleBatchContinuesAndBoundsErrors(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing.txt")
	if err := os.WriteFile(existing, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths := []string{existing}
	for i := 0; i < 12; i++ {
		paths = append(paths, filepath.Join(root, fmt.Sprintf("missing-%02d.txt", i)))
	}

	result, out, err := Handle(t.Context(), nil, DeleteInput{FilePaths: paths})
	if err != nil || !result.IsError {
		t.Fatalf("Handle() should report partial failure: result=%+v err=%v", result, err)
	}
	for _, want := range []string{"PARTIAL: deleted 1/13 targets", "12 errors", "2 additional errors omitted"} {
		if !strings.Contains(out.Result, want) {
			t.Fatalf("partial output %q does not contain %q", out.Result, want)
		}
	}
	if got := strings.Count(out.Result, "- file_paths["); got != maxBatchErrors {
		t.Fatalf("reported error details = %d, want %d", got, maxBatchErrors)
	}
	if _, err := os.Stat(existing); !os.IsNotExist(err) {
		t.Fatalf("successful batch target still exists: %v", err)
	}
}

func TestHandleBatchRejectsInvalidSetsBeforeDeleting(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "keep.txt")
	if err := os.WriteFile(file, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input DeleteInput
		want  string
	}{
		{name: "mixed fields", input: DeleteInput{FilePath: file, FilePaths: []string{file}}, want: "cannot be combined"},
		{name: "duplicate", input: DeleteInput{FilePaths: []string{file, file}}, want: "duplicates"},
		{name: "overlap", input: DeleteInput{FilePaths: []string{root, file}, Recursive: true}, want: "overlap"},
		{name: "too many", input: DeleteInput{FilePaths: makePaths(root, maxBatchPaths+1)}, want: "maximum is 100"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, out, err := Handle(t.Context(), nil, tt.input)
			if err != nil || !result.IsError {
				t.Fatalf("Handle() should reject invalid batch: result=%+v err=%v", result, err)
			}
			if !strings.Contains(out.Result, tt.want) {
				t.Fatalf("error %q does not contain %q", out.Result, tt.want)
			}
			if _, err := os.Stat(file); err != nil {
				t.Fatalf("preflight failure modified target: %v", err)
			}
		})
	}
}

func makePaths(root string, count int) []string {
	paths := make([]string, count)
	for i := range paths {
		paths[i] = filepath.Join(root, fmt.Sprintf("file-%03d.txt", i))
	}
	return paths
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
