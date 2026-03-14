package patch

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxPatchSize는 패치 텍스트의 최대 크기이다 (OOM 방지).
const maxPatchSize = 10 * 1024 * 1024 // 10MB

type PatchInput struct {
	FilePath string `json:"file_path" jsonschema:"Absolute path to the file to patch"`
	Patch    string `json:"patch" jsonschema:"Unified diff text (output of the diff tool)"`
	DryRun   bool   `json:"dry_run,omitempty" jsonschema:"Preview patch result without modifying the file (default false)"`
}

type PatchOutput struct {
	Result string `json:"result"`
}

var reHunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

type hunk struct {
	srcStart int // 1-based
	srcCount int
	dstStart int
	dstCount int
	lines    []hunkLine
}

type hunkLine struct {
	op   byte // ' ', '-', '+'
	text string
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input PatchInput) (*mcp.CallToolResult, PatchOutput, error) {
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}
	if input.Patch == "" {
		return errorResult("patch is required")
	}

	// 패치 텍스트 크기 제한 (OOM 방지)
	if len(input.Patch) > maxPatchSize {
		return errorResult(fmt.Sprintf("patch too large (%d bytes, max %d bytes)", len(input.Patch), maxPatchSize))
	}

	// 패치 파싱
	hunks, err := parseUnifiedDiff(input.Patch)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to parse patch: %v", err))
	}
	if len(hunks) == 0 {
		return errorResult("no hunks found in patch")
	}

	// 파일 읽기 (인코딩 인식)
	hintCharset := edit.FindEditorConfigCharset(input.FilePath)
	content, encInfo, err := common.ReadFileWithEncoding(input.FilePath, hintCharset)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file: %v", err))
	}

	// CRLF → LF 정규화
	lineEnding := "\n"
	if strings.Contains(content, "\r\n") {
		lineEnding = "\r\n"
		content = strings.ReplaceAll(content, "\r\n", "\n")
	}

	// 줄 분할
	lines := strings.Split(content, "\n")
	// trailing empty line 처리
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	// hunk 적용 (역순 — 뒤에서부터 적용해야 줄번호가 밀리지 않음)
	for i := len(hunks) - 1; i >= 0; i-- {
		h := hunks[i]
		startIdx := h.srcStart - 1 // 0-based

		// startIdx 유효성 검증
		if startIdx < 0 {
			return errorResult(fmt.Sprintf("hunk %d: invalid source start line %d", i+1, h.srcStart))
		}
		if startIdx > len(lines) {
			return errorResult(fmt.Sprintf("hunk %d: source start line %d exceeds file length %d", i+1, h.srcStart, len(lines)))
		}

		// context line 검증 + 실제 소스 라인 수 카운트
		srcIdx := startIdx
		srcConsumed := 0
		for _, hl := range h.lines {
			if hl.op == ' ' || hl.op == '-' {
				if srcIdx >= len(lines) {
					return errorResult(fmt.Sprintf("hunk %d: context mismatch at line %d (file has only %d lines)", i+1, srcIdx+1, len(lines)))
				}
				if hl.text != lines[srcIdx] {
					return errorResult(fmt.Sprintf("hunk %d: context mismatch at line %d:\n  expected: %q\n  actual:   %q", i+1, srcIdx+1, hl.text, lines[srcIdx]))
				}
				srcIdx++
				srcConsumed++
			}
		}

		// 치환 적용
		var newLines []string
		srcIdx = startIdx
		for _, hl := range h.lines {
			switch hl.op {
			case ' ':
				if srcIdx >= len(lines) {
					return errorResult(fmt.Sprintf("hunk %d: index out of range at line %d during apply", i+1, srcIdx+1))
				}
				newLines = append(newLines, lines[srcIdx])
				srcIdx++
			case '-':
				if srcIdx >= len(lines) {
					return errorResult(fmt.Sprintf("hunk %d: index out of range at line %d during apply", i+1, srcIdx+1))
				}
				srcIdx++ // 삭제 — 건너뜀
			case '+':
				newLines = append(newLines, hl.text)
			}
		}

		// lines 교체 (실제 소비한 줄 수 사용 — 헤더의 srcCount가 아닌 실측값)
		result := make([]string, 0, len(lines)-srcConsumed+len(newLines))
		result = append(result, lines[:startIdx]...)
		result = append(result, newLines...)
		result = append(result, lines[startIdx+srcConsumed:]...)
		lines = result
	}

	// 결과 조합
	output := strings.Join(lines, "\n")
	if output != "" {
		output += "\n" // trailing newline 복원
	}

	// 원래 줄바꿈 복원
	if lineEnding == "\r\n" {
		output = strings.ReplaceAll(output, "\n", "\r\n")
	}

	if input.DryRun {
		// 줄 수 변화 계산
		origLineCount := len(strings.Split(content, "\n"))
		newLineCount := len(lines)
		delta := newLineCount - origLineCount
		sign := "+"
		if delta < 0 {
			sign = ""
		}
		msg := fmt.Sprintf("[DRY RUN] patch would apply %d hunk(s) to %s (lines: %d → %d, %s%d)",
			len(hunks), input.FilePath, origLineCount, newLineCount, sign, delta)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, PatchOutput{Result: msg}, nil
	}

	// 파일 쓰기 (인코딩 보존)
	if err := common.WriteFileWithEncoding(input.FilePath, output, encInfo); err != nil {
		return errorResult(fmt.Sprintf("failed to write file: %v", err))
	}

	msg := fmt.Sprintf("OK: applied %d hunk(s) to %s (encoding=%s)", len(hunks), input.FilePath, encInfo.Charset)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, PatchOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "patch",
		Description: `Applies a unified diff patch to a file.
Parses @@ hunk headers, verifies context lines, and applies changes.
Encoding-aware: preserves original file encoding.
Use dry_run=true to preview without modifying the file.`,
	}, Handle)
}

// parseUnifiedDiff는 unified diff 문자열에서 hunk들을 추출한다.
func parseUnifiedDiff(patch string) ([]hunk, error) {
	// CRLF 정규화
	patch = strings.ReplaceAll(patch, "\r\n", "\n")
	// trailing newlines 제거
	patch = strings.TrimRight(patch, "\n")
	lines := strings.Split(patch, "\n")

	var hunks []hunk
	var current *hunk

	for _, line := range lines {
		// --- / +++ 헤더 스킵
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") {
			continue
		}

		if m := reHunkHeader.FindStringSubmatch(line); m != nil {
			srcStart, err := strconv.Atoi(m[1])
			if err != nil || srcStart < 0 {
				return nil, fmt.Errorf("invalid hunk srcStart: %q", m[1])
			}
			srcCount := 1
			if m[2] != "" {
				srcCount, err = strconv.Atoi(m[2])
				if err != nil || srcCount < 0 {
					return nil, fmt.Errorf("invalid hunk srcCount: %q", m[2])
				}
			}
			dstStart, err := strconv.Atoi(m[3])
			if err != nil || dstStart < 0 {
				return nil, fmt.Errorf("invalid hunk dstStart: %q", m[3])
			}
			dstCount := 1
			if m[4] != "" {
				dstCount, err = strconv.Atoi(m[4])
				if err != nil || dstCount < 0 {
					return nil, fmt.Errorf("invalid hunk dstCount: %q", m[4])
				}
			}

			hunks = append(hunks, hunk{
				srcStart: srcStart,
				srcCount: srcCount,
				dstStart: dstStart,
				dstCount: dstCount,
			})
			current = &hunks[len(hunks)-1]
			continue
		}

		if current == nil {
			continue
		}

		if len(line) == 0 {
			// 빈 줄은 context 줄로 처리 (실제 diff에서 빈 context line = " " 접두사 없는 빈 줄)
			current.lines = append(current.lines, hunkLine{op: ' ', text: ""})
			continue
		}

		op := line[0]
		text := line[1:]
		switch op {
		case ' ':
			current.lines = append(current.lines, hunkLine{op: ' ', text: text})
		case '-':
			current.lines = append(current.lines, hunkLine{op: '-', text: text})
		case '+':
			current.lines = append(current.lines, hunkLine{op: '+', text: text})
		case '\\':
			// "\ No newline at end of file" — 무시
		default:
			// hunk 밖의 일반 텍스트 — 무시
		}
	}

	return hunks, nil
}

func errorResult(msg string) (*mcp.CallToolResult, PatchOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, PatchOutput{Result: msg}, nil
}
