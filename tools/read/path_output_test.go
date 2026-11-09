package read_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-tool/common"
	copytool "agent-tool/tools/copy"
	"agent-tool/tools/edit"
	"agent-tool/tools/multiread"
	"agent-tool/tools/read"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestWorkspaceRelativeOutputPreservesFileContent(t *testing.T) {
	root := t.TempDir()
	old := common.GetWorkspace()
	common.SetWorkspace(root)
	t.Cleanup(func() { common.SetWorkspace(old) })
	for _, p := range []string{"a/connection.go", "a/b/connection.go"} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("original "+root+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, multi, err := multiread.Handle(t.Context(), nil, multiread.MultiReadInput{FilePaths: []string{filepath.Join(root, "a/connection.go"), "a/b/connection.go"}})
	if err != nil || multi.ErrorCount != 0 || !strings.Contains(multi.Content, "=== a/connection.go ===") || !strings.Contains(multi.Content, "=== a/b/connection.go ===") {
		t.Fatalf("multiread: %v %+v", err, multi)
	}
	if !strings.Contains(multi.Content, "original "+root) {
		t.Fatal("multiread changed file content")
	}
	_, edited, err := edit.Handle(t.Context(), nil, edit.EditInput{FilePath: filepath.Join(root, "a/connection.go"), OldString: "original", NewString: "changed"})
	if err != nil || strings.Contains(edited.Result, root) || !strings.Contains(edited.Result, "a/connection.go") {
		t.Fatalf("edit: %v %+v", err, edited)
	}
	_, copied, err := copytool.Handle(t.Context(), nil, copytool.CopyInput{Source: filepath.Join(root, "a/connection.go"), Destination: "copied.go"})
	if err != nil || strings.Contains(copied.Result, root) || !strings.Contains(copied.Result, "copied.go") {
		t.Fatalf("copy: %v %+v", err, copied)
	}
	_, content, err := read.Handle(t.Context(), nil, read.ReadInput{FilePath: "copied.go"})
	if err != nil || !strings.Contains(content.Content, "changed "+root) {
		t.Fatalf("read/content changed: %v %+v", err, content)
	}
	result, missing, err := read.Handle(t.Context(), nil, read.ReadInput{FilePath: filepath.Join(root, "missing.go")})
	message := result.Content[0].(*mcp.TextContent).Text
	if err != nil || !result.IsError || strings.Contains(message, root) || !strings.Contains(message, "missing.go") {
		t.Fatalf("read missing: %v %+v", err, missing)
	}
	outside := filepath.Join(t.TempDir(), "outside.go")
	if common.DisplayPath(root, outside) != outside {
		t.Fatal("outside path was disguised as local")
	}
}
