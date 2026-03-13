package edit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// EditInput은 Edit 도구의 입력 파라미터이다.
type EditInput struct {
	FilePath    string `json:"file_path" jsonschema:"description=Absolute path to the file to edit"`
	OldString   string `json:"old_string" jsonschema:"description=Exact text to find in the file"`
	NewString   string `json:"new_string" jsonschema:"description=Replacement text (must differ from old_string)"`
	ReplaceAll  bool   `json:"replace_all" jsonschema:"description=Replace all occurrences instead of just the first (default false)"`
	IndentStyle string `json:"indent_style" jsonschema:"description=Override indentation style. Values: tabs or spaces-N (e.g. spaces-4). Empty = auto-detect (default)"`
}

// EditOutput은 Edit 도구의 출력이다.
type EditOutput struct {
	Result string `json:"result"`
}

// Handle은 Edit 도구의 MCP 핸들러이다.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input EditInput) (*mcp.CallToolResult, EditOutput, error) {
	// 입력 검증
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}
	if input.OldString == "" {
		return errorResult("old_string is required")
	}
	if input.OldString == input.NewString {
		return errorResult("old_string and new_string must be different")
	}

	// 파일 존재 확인
	if _, err := os.Stat(input.FilePath); err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", input.FilePath))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}

	// .editorconfig에서 charset 힌트 가져오기
	hintCharset := FindEditorConfigCharset(input.FilePath)

	// 파일 읽기 (인코딩 감지 포함)
	content, encInfo, err := common.ReadFileWithEncoding(input.FilePath, hintCharset)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file: %v", err))
	}

	// 들여쓰기 스타일 결정
	var fileStyle IndentStyle
	if input.IndentStyle != "" {
		parsed, err := parseIndentStyleOption(input.IndentStyle)
		if err != nil {
			return errorResult(fmt.Sprintf("invalid indent_style: %v", err))
		}
		fileStyle = parsed
	} else {
		fileStyle = DetectIndent(input.FilePath, content)
	}

	// 치환 실행 (indent_style 명시 지정 시 new_string도 fileStyle로 강제 변환)
	forceStyle := input.IndentStyle != ""
	result := Replace(content, input.OldString, input.NewString, input.ReplaceAll, fileStyle, forceStyle)
	if !result.Applied {
		return errorResult(result.Message)
	}

	// 파일 쓰기 (원본 인코딩 보존)
	if err := common.WriteFileWithEncoding(input.FilePath, result.Content, encInfo); err != nil {
		return errorResult(fmt.Sprintf("failed to write file: %v", err))
	}

	msg := fmt.Sprintf("OK: %s (%s, encoding=%s)", result.Message, input.FilePath, encInfo.Charset)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, EditOutput{Result: msg}, nil
}

// Register는 MCP 서버에 Edit 도구를 등록한다.
func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "edit",
		Description: `Replaces old_string with new_string in the specified file.
Smart indentation: auto-converts between tabs and spaces to match the file's style.
Encoding-aware: preserves original file encoding (UTF-8, EUC-KR, Shift-JIS, UTF-8 BOM, etc.).
Reads .editorconfig for indentation settings.`,
	}, Handle)
}

// parseIndentStyleOption은 indent_style 옵션 문자열을 파싱한다.
// "tabs" → UseTabs=true, "spaces-4" → UseTabs=false, IndentSize=4
func parseIndentStyleOption(s string) (IndentStyle, error) {
	s = strings.ToLower(strings.TrimSpace(s))

	if s == "tabs" || s == "tab" {
		return IndentStyle{UseTabs: true, IndentSize: 4}, nil
	}

	if strings.HasPrefix(s, "spaces-") || strings.HasPrefix(s, "space-") {
		parts := strings.SplitN(s, "-", 2)
		if len(parts) == 2 {
			n, err := strconv.Atoi(parts[1])
			if err != nil || n < 1 || n > 8 {
				return IndentStyle{}, fmt.Errorf("invalid indent size: %s (must be 1-8)", parts[1])
			}
			return IndentStyle{UseTabs: false, IndentSize: n}, nil
		}
	}

	if s == "spaces" || s == "space" {
		return IndentStyle{UseTabs: false, IndentSize: 4}, nil
	}

	return IndentStyle{}, fmt.Errorf("expected 'tabs', 'spaces', or 'spaces-N' (e.g. spaces-4), got '%s'", s)
}

func errorResult(msg string) (*mcp.CallToolResult, EditOutput, error) {
	r := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
	return r, EditOutput{Result: msg}, nil
}
