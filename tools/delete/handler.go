package delete

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type DeleteInput struct {
	FilePath string `json:"file_path" jsonschema:"Absolute path to the file to delete"`
	DryRun   bool   `json:"dry_run" jsonschema:"Preview deletion without actually removing the file (default false)"`
}

type DeleteOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input DeleteInput) (*mcp.CallToolResult, DeleteOutput, error) {
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}

	// 경로 정규화 + ".." 트래버설 차단
	cleaned := filepath.Clean(input.FilePath)
	if strings.Contains(cleaned, "..") {
		return errorResult("path traversal (..) is not allowed")
	}

	// 파일 정보 확인
	info, err := os.Lstat(cleaned) // Lstat: 심볼릭 링크를 따라가지 않음
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", cleaned))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}

	// 디렉토리 삭제 금지
	if info.IsDir() {
		return errorResult("directory deletion is not allowed. Only individual files can be deleted")
	}

	// 심볼릭 링크 삭제 금지
	if info.Mode()&os.ModeSymlink != 0 {
		return errorResult("symlink deletion is not allowed for safety")
	}

	// dry_run 모드
	if input.DryRun {
		msg := fmt.Sprintf("[DRY RUN] would delete: %s (%d bytes)", cleaned, info.Size())
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, DeleteOutput{Result: msg}, nil
	}

	// 실제 삭제
	if err := os.Remove(cleaned); err != nil {
		return errorResult(fmt.Sprintf("delete failed: %v", err))
	}

	msg := fmt.Sprintf("OK: deleted %s (%d bytes)", cleaned, info.Size())
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, DeleteOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete",
		Description: "Deletes a single file. Safety: no directory deletion, no symlinks, no path traversal. Use dry_run=true to preview.",
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, DeleteOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, DeleteOutput{Result: msg}, nil
}
