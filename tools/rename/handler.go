package rename

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RenameInput struct {
	OldPath string `json:"old_path" jsonschema:"Absolute path to the file or directory to rename"`
	NewPath string `json:"new_path" jsonschema:"Absolute path for the new name/location"`
	DryRun  bool   `json:"dry_run" jsonschema:"Preview rename without actually moving the file (default false)"`
}

type RenameOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input RenameInput) (*mcp.CallToolResult, RenameOutput, error) {
	if input.OldPath == "" || input.NewPath == "" {
		return errorResult("both old_path and new_path are required")
	}
	if !filepath.IsAbs(input.OldPath) || !filepath.IsAbs(input.NewPath) {
		return errorResult("both paths must be absolute")
	}

	oldCleaned := filepath.Clean(input.OldPath)
	newCleaned := filepath.Clean(input.NewPath)

	// ".." 트래버설 차단
	for _, p := range []string{oldCleaned, newCleaned} {
		for _, part := range strings.Split(filepath.ToSlash(p), "/") {
			if part == ".." {
				return errorResult("path traversal (..) is not allowed")
			}
		}
	}

	// 같은 경로인지 확인
	if oldCleaned == newCleaned {
		return errorResult("old_path and new_path are the same")
	}

	// 원본 존재 확인
	oldInfo, err := os.Stat(oldCleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("source not found: %s", oldCleaned))
		}
		return errorResult(fmt.Sprintf("cannot access source: %v", err))
	}

	// 대상 경로에 이미 파일이 있는지 확인
	if _, err := os.Stat(newCleaned); err == nil {
		return errorResult(fmt.Sprintf("destination already exists: %s", newCleaned))
	}

	// 대상 디렉토리 존재 확인
	newDir := filepath.Dir(newCleaned)
	if _, err := os.Stat(newDir); os.IsNotExist(err) {
		return errorResult(fmt.Sprintf("destination directory does not exist: %s", newDir))
	}

	kind := "file"
	if oldInfo.IsDir() {
		kind = "directory"
	}

	// dry_run
	if input.DryRun {
		msg := fmt.Sprintf("[DRY RUN] would rename %s: %s → %s", kind, oldCleaned, newCleaned)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, RenameOutput{Result: msg}, nil
	}

	// 실제 이름 변경 (os.Rename은 원자적)
	if err := os.Rename(oldCleaned, newCleaned); err != nil {
		return errorResult(fmt.Sprintf("rename failed: %v", err))
	}

	msg := fmt.Sprintf("OK: renamed %s: %s → %s", kind, oldCleaned, newCleaned)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, RenameOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "rename",
		Description: "Renames or moves a file/directory. Atomic operation via os.Rename. Use dry_run=true to preview.",
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, RenameOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, RenameOutput{Result: msg}, nil
}
