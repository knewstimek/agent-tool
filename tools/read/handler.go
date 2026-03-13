package read

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ReadInput struct {
	FilePath string `json:"file_path" jsonschema:"description=Absolute path to the file to read"`
	Offset   int    `json:"offset" jsonschema:"description=Line number to start reading from (1-based). Default: 1"`
	Limit    int    `json:"limit" jsonschema:"description=Maximum number of lines to read. Default: 0 (all)"`
}

type ReadOutput struct {
	Content    string `json:"content"`
	Encoding   string `json:"encoding"`
	TotalLines int    `json:"total_lines"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ReadInput) (*mcp.CallToolResult, ReadOutput, error) {
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}

	fi, err := os.Stat(input.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", input.FilePath))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}
	if fi.IsDir() {
		return errorResult(fmt.Sprintf("path is a directory, not a file: %s", input.FilePath))
	}

	// .editorconfig charset 힌트
	hintCharset := edit.FindEditorConfigCharset(input.FilePath)

	// 인코딩 감지하여 읽기
	content, encInfo, err := common.ReadFileWithEncoding(input.FilePath, hintCharset)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file: %v", err))
	}

	lines := strings.Split(content, "\n")
	totalLines := len(lines)

	// offset/limit 적용
	offset := input.Offset
	if offset < 1 {
		offset = 1
	}
	if offset > totalLines {
		offset = totalLines
	}

	startIdx := offset - 1 // 0-based
	endIdx := totalLines
	if input.Limit > 0 && startIdx+input.Limit < endIdx {
		endIdx = startIdx + input.Limit
	}

	// 줄 번호 포맷 (cat -n 스타일)
	var sb strings.Builder
	for i := startIdx; i < endIdx; i++ {
		fmt.Fprintf(&sb, "%6d\t%s\n", i+1, lines[i])
	}

	result := sb.String()

	// 인코딩 감지 신뢰도가 낮으면 경고 추가
	if warning := common.EncodingWarning(encInfo); warning != "" {
		result += warning
	}

	out := ReadOutput{
		Content:    result,
		Encoding:   encInfo.Charset,
		TotalLines: totalLines,
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, out, nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "read",
		Description: `Reads a file and returns its contents with line numbers.
Encoding-aware: auto-detects file encoding (UTF-8, EUC-KR, Shift-JIS, etc.).
Supports offset/limit for reading specific line ranges.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, ReadOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ReadOutput{}, nil
}
