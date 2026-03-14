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
	FilePath    string `json:"file_path" jsonschema:"Absolute path to the file to edit"`
	OldString   string `json:"old_string" jsonschema:"Exact text to find in the file"`
	NewString   string `json:"new_string" jsonschema:"Replacement text (must differ from old_string)"`
	ReplaceAll  bool   `json:"replace_all,omitempty" jsonschema:"Replace all occurrences instead of just the first (default false)"`
	DryRun      bool   `json:"dry_run,omitempty" jsonschema:"Preview changes without modifying the file (default false)"`
	IndentStyle string `json:"indent_style,omitempty" jsonschema:"Override indentation style. Values: tabs or spaces-N (e.g. spaces-4). Empty = auto-detect (default)"`
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

	// dry-run이면 쓰기 없이 결과 미리보기 반환
	if input.DryRun {
		preview := dryRunPreview(content, result.Content, input.FilePath)
		msg := fmt.Sprintf("[DRY RUN] would %s (%s, encoding=%s)\n\n%s", result.Message, input.FilePath, encInfo.Charset, preview)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, EditOutput{Result: msg}, nil
	}

	// 파일 쓰기 (원본 인코딩 보존)
	if err := common.WriteFileWithEncoding(input.FilePath, result.Content, encInfo); err != nil {
		return errorResult(fmt.Sprintf("failed to write file: %v", err))
	}

	msg := fmt.Sprintf("OK: %s (%s, encoding=%s)", result.Message, input.FilePath, encInfo.Charset)

	// 인코딩 감지 신뢰도가 낮으면 경고 추가
	if warning := common.EncodingWarning(encInfo); warning != "" {
		msg += warning
	}

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
Reads .editorconfig for indentation settings.
Use dry_run=true to preview changes without modifying the file.`,
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

// dryRunPreview는 변경 전후의 차이를 간단한 diff 형식으로 보여준다.
// 변경된 줄 주변 context 3줄을 포함한다.
func dryRunPreview(before, after, filePath string) string {
	oldLines := strings.Split(before, "\n")
	newLines := strings.Split(after, "\n")

	// 변경된 범위 찾기 (앞뒤 공통 부분 제거)
	prefixLen := 0
	minLen := len(oldLines)
	if len(newLines) < minLen {
		minLen = len(newLines)
	}
	for prefixLen < minLen && oldLines[prefixLen] == newLines[prefixLen] {
		prefixLen++
	}

	suffixLen := 0
	for suffixLen < minLen-prefixLen &&
		oldLines[len(oldLines)-1-suffixLen] == newLines[len(newLines)-1-suffixLen] {
		suffixLen++
	}

	// context 범위 계산
	ctxStart := prefixLen - 3
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEndOld := len(oldLines) - suffixLen + 3
	if ctxEndOld > len(oldLines) {
		ctxEndOld = len(oldLines)
	}
	ctxEndNew := len(newLines) - suffixLen + 3
	if ctxEndNew > len(newLines) {
		ctxEndNew = len(newLines)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- %s (before)\n+++ %s (after)\n", filePath, filePath))

	// 공통 앞부분 context
	for i := ctxStart; i < prefixLen; i++ {
		sb.WriteString(" " + oldLines[i] + "\n")
	}
	// 삭제된 줄
	for i := prefixLen; i < len(oldLines)-suffixLen; i++ {
		sb.WriteString("-" + oldLines[i] + "\n")
	}
	// 추가된 줄
	for i := prefixLen; i < len(newLines)-suffixLen; i++ {
		sb.WriteString("+" + newLines[i] + "\n")
	}
	// 공통 뒷부분 context
	endOld := len(oldLines) - suffixLen
	for i := endOld; i < ctxEndOld; i++ {
		sb.WriteString(" " + oldLines[i] + "\n")
	}

	return sb.String()
}

func errorResult(msg string) (*mcp.CallToolResult, EditOutput, error) {
	r := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
	return r, EditOutput{Result: msg}, nil
}
