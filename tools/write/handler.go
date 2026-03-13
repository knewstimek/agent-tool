package write

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type WriteInput struct {
	FilePath string `json:"file_path" jsonschema:"description=Absolute path to the file to write"`
	Content  string `json:"content" jsonschema:"description=Content to write to the file"`
}

type WriteOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input WriteInput) (*mcp.CallToolResult, WriteOutput, error) {
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}

	// 디렉토리 자동 생성
	dir := filepath.Dir(input.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errorResult(fmt.Sprintf("failed to create directory: %v", err))
	}

	// 기존 파일이 있으면 인코딩 정보를 보존
	var encInfo common.EncodingInfo

	if fi, err := os.Stat(input.FilePath); err == nil {
		if fi.IsDir() {
			return errorResult(fmt.Sprintf("path is a directory: %s", input.FilePath))
		}
		// 기존 파일의 인코딩 감지
		hintCharset := edit.FindEditorConfigCharset(input.FilePath)
		_, encInfo, err = common.ReadFileWithEncoding(input.FilePath, hintCharset)
		if err != nil {
			// 읽기 실패해도 새로 쓰기는 가능 (UTF-8 기본)
			encInfo = common.EncodingInfo{Charset: "UTF-8"}
		}
	} else {
		// 새 파일: .editorconfig charset 힌트 확인, 없으면 UTF-8
		hintCharset := edit.FindEditorConfigCharset(input.FilePath)
		if hintCharset != "" {
			encInfo = common.EncodingInfo{Charset: hintCharset}
		} else {
			encInfo = common.EncodingInfo{Charset: "UTF-8"}
		}
	}

	// 파일 쓰기
	if err := common.WriteFileWithEncoding(input.FilePath, input.Content, encInfo); err != nil {
		return errorResult(fmt.Sprintf("failed to write file: %v", err))
	}

	msg := fmt.Sprintf("OK: file written (%s, encoding=%s)", input.FilePath, encInfo.Charset)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, WriteOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "write",
		Description: `Creates or overwrites a file with the given content.
Encoding-aware: preserves original encoding for existing files, uses .editorconfig hints for new files.
Auto-creates parent directories if they don't exist.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, WriteOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, WriteOutput{Result: msg}, nil
}
