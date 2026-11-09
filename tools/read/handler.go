package read

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// imageExts maps file extensions to MIME types for image files.
var imageExts = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".bmp":  "image/bmp",
	".webp": "image/webp",
	".ico":  "image/x-icon",
	".svg":  "image/svg+xml",
	".tiff": "image/tiff",
	".tif":  "image/tiff",
}

// maxImageSize is the maximum image file size we'll return as base64 (20MB).
const maxImageSize = 20 * 1024 * 1024

// readHashThreshold is the maximum file size for automatically including a hash.
// Files larger than this require a separate call to the checksum tool.
const readHashThreshold = 10 * 1024 * 1024 // 10MB

type ReadInput struct {
	Encoding       string `json:"encoding,omitempty" jsonschema:"Charset override, e.g. EUC-KR or Shift_JIS; overrides .editorconfig, BOM takes priority"`
	FilePath       string `json:"file_path,omitempty" jsonschema:"Workspace-relative, absolute, or @directory_alias/subpath"`
	Path           string `json:"path,omitempty" jsonschema:"Alias for file_path"`
	Offset         any    `json:"offset,omitempty" jsonschema:"Start line: 1-based integer, negative from end, 'start-end', or [start,end]; default 1"`
	Limit          *int   `json:"limit,omitempty" jsonschema:"Line limit; default 400. Use 0 or all=true for no line cap"`
	StartLine      *int   `json:"start_line,omitempty" jsonschema:"Alias for offset"`
	EndLine        *int   `json:"end_line,omitempty" jsonschema:"Inclusive end with start_line"`
	All            bool   `json:"all,omitempty" jsonschema:"Disable line cap; character cap remains"`
	MaxOutputChars int    `json:"max_output_chars,omitempty" jsonschema:"Output character cap; default 32768, min 256, max 131072"`
	MaxLineChars   int    `json:"max_line_chars,omitempty" jsonschema:"Per-line character cap; default 4000, max 32768"`
	IncludeHash    *bool  `json:"include_hash,omitempty" jsonschema:"Include SHA-256; default true"`
}

type ReadOutput struct {
	Content       string `json:"content"`
	Encoding      string `json:"encoding"`
	TotalLines    int    `json:"total_lines"`
	Hash          string `json:"hash,omitempty"`
	ReturnedLines int    `json:"returned_lines"`
	Truncated     bool   `json:"truncated"`
	NextOffset    int    `json:"next_offset,omitempty"`
}

const (
	defaultLineLimit    = 400
	defaultMaxLineChars = 4000
)

// parseFlexOffset accepts integer, "N", "N-M" range string, "[N, M]" string,
// or [N, M] array. Agents sometimes pass offset as a string or array instead
// of a plain integer; this function normalizes all forms.
// Returns (offset, rangeLimit). rangeLimit > 0 indicates a range was given.
func parseFlexOffset(v any) (int, int, error) {
	switch val := v.(type) {
	case nil:
		return 0, 0, nil
	case float64:
		if n, ok := asInt(val); ok {
			return n, 0, nil
		}
		return 0, 0, fmt.Errorf("offset must be a finite integer within range")
	case int:
		return val, 0, nil
	case string:
		val = strings.TrimSpace(val)
		if val == "" {
			return 0, 0, nil
		}
		// Strip array brackets: "[370, 396]" -> "370, 396"
		if len(val) >= 2 && val[0] == '[' && val[len(val)-1] == ']' {
			val = strings.TrimSpace(val[1 : len(val)-1])
		}
		// Comma-separated range: "370, 396"
		if parts := strings.SplitN(val, ",", 2); len(parts) == 2 {
			s, e1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			e, e2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if e1 == nil && e2 == nil {
				if e < s {
					s, e = e, s
				}
				return checkedOffsetRange(s, e)
			}
		}
		// Dash range: "370-396" (parts[0]!="" prevents matching negative like "-5")
		if parts := strings.SplitN(val, "-", 2); len(parts) == 2 && parts[0] != "" {
			s, e1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			e, e2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if e1 == nil && e2 == nil {
				if e < s {
					s, e = e, s
				}
				return checkedOffsetRange(s, e)
			}
		}
		// Plain number
		n, err := strconv.Atoi(val)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid offset %q -- use integer, 'start-end', or [start, end]", v)
		}
		return n, 0, nil
	case []interface{}:
		if len(val) == 2 {
			s, ok1 := asInt(val[0])
			e, ok2 := asInt(val[1])
			if ok1 && ok2 {
				if e < s {
					s, e = e, s
				}
				return checkedOffsetRange(s, e)
			}
		}
		return 0, 0, fmt.Errorf("invalid offset array -- expected [start, end] integers")
	default:
		return 0, 0, fmt.Errorf("invalid offset type %T -- use integer or string", v)
	}
}

func checkedOffsetRange(start, end int) (int, int, error) {
	if start == 0 {
		start = 1
	}
	if end == 0 {
		end = 1
	}
	if end < start {
		start, end = end, start
	}
	if start < 0 && end > 0 {
		return 0, 0, fmt.Errorf("range endpoints must both be positive or both negative")
	}
	maxInt := int(^uint(0) >> 1)
	if end-start == maxInt {
		return 0, 0, fmt.Errorf("offset range is too large")
	}
	return start, end - start + 1, nil
}

func asInt(v interface{}) (int, bool) {
	switch val := v.(type) {
	case float64:
		maxInt := int(^uint(0) >> 1)
		if math.IsNaN(val) || math.IsInf(val, 0) || math.Trunc(val) != val ||
			val < -float64(maxInt)-1 || val >= float64(maxInt) {
			return 0, false
		}
		return int(val), true
	case int:
		return val, true
	default:
		return 0, false
	}
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ReadInput) (*mcp.CallToolResult, ReadOutput, error) {
	// Accept "path" as an alias for "file_path"
	if input.FilePath == "" {
		input.FilePath = input.Path
	}

	// Accept start_line/end_line as aliases for offset/limit
	if input.StartLine != nil && input.Offset == nil {
		input.Offset = *input.StartLine
	}
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	resolvedPath, err := common.ResolveRequestPath(ctx, req, input.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot resolve path: %v", err))
	}
	input.FilePath = resolvedPath

	fi, err := os.Stat(input.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", common.DisplayRequestPath(ctx, req, input.FilePath)))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}
	if fi.IsDir() {
		return errorResult(fmt.Sprintf("path is a directory, not a file: %s", common.DisplayRequestPath(ctx, req, input.FilePath)))
	}

	// Image files: return as MCP ImageContent (base64-encoded)
	ext := strings.ToLower(filepath.Ext(input.FilePath))
	if mime, isImage := imageExts[ext]; isImage {
		return handleImage(input.FilePath, fi, mime)
	}

	// .editorconfig charset hint
	hintCharset := strings.TrimSpace(input.Encoding)
	if hintCharset == "" {
		hintCharset = edit.FindEditorConfigCharset(input.FilePath)
	}

	// Read with encoding detection
	includeHash := input.IncludeHash == nil || *input.IncludeHash
	reader := common.ReadFileWithEncoding
	if includeHash {
		reader = common.ReadFileWithEncodingHash
	}
	content, encInfo, err := reader(input.FilePath, hintCharset)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file: %v", err))
	}

	// Match bufio.ScanLines semantics: a final newline terminates the last line
	// and does not create a phantom continuation line.
	totalLines := common.TextLineCount(content)

	offset, rangeLimit, err := parseFlexOffset(input.Offset)
	if err != nil {
		return errorResult(err.Error())
	}

	limit := 0
	limitProvided := input.Limit != nil
	if limitProvided {
		limit = *input.Limit
		if limit < 0 {
			return errorResult("limit must be non-negative")
		}
	}
	// Range (e.g. "100-200") sets limit when explicit limit is not provided
	if rangeLimit > 0 && !limitProvided {
		limit = rangeLimit
		limitProvided = true
	}
	if !limitProvided && !input.All {
		limit = defaultLineLimit
	}

	maxOutputChars := input.MaxOutputChars
	if maxOutputChars <= 0 {
		maxOutputChars = common.DefaultOutputChars
	}
	if maxOutputChars < 256 {
		return errorResult("max_output_chars must be at least 256 for content and continuation metadata")
	}
	if maxOutputChars > common.HardOutputChars {
		return errorResult(fmt.Sprintf("max_output_chars must be at most %d", common.HardOutputChars))
	}
	maxLineChars := input.MaxLineChars
	if maxLineChars <= 0 {
		maxLineChars = defaultMaxLineChars
	}
	if maxLineChars > common.DefaultOutputChars {
		return errorResult(fmt.Sprintf("max_line_chars must be at most %d", common.DefaultOutputChars))
	}

	var startIdx, endIdx int

	if totalLines == 0 {
		startIdx = 0
	} else if offset < 0 {
		// Negative index: calculate from the end
		startIdx = totalLines + offset
		if startIdx < 0 {
			startIdx = 0
		}
	} else {
		if offset < 1 {
			offset = 1
		}
		if offset > totalLines {
			startIdx = totalLines
		} else {
			startIdx = offset - 1
		}
	}

	endIdx = totalLines
	if limit > 0 && limit < endIdx-startIdx {
		endIdx = startIdx + limit
	}

	if input.EndLine != nil {
		if *input.EndLine < 1 || *input.EndLine < startIdx+1 {
			return errorResult("end_line must be positive and at or after the resolved start line")
		}
		if *input.EndLine < endIdx {
			endIdx = *input.EndLine
		}
	}

	// Process only the needed range. The scanner buffer is raised to the decoded
	// file size so a single long line is handled explicitly by max_line_chars
	// instead of disappearing behind Scanner's 64 KiB default token limit.
	var sb strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), len(content)+1)
	scanner.Split(common.ScanTextLines)
	lineNum := 0
	returnedLines := 0
	outputTruncated := false
	lineTruncated := false
	nextOffset := 0
	contentBudget := maxOutputChars - min(512, maxOutputChars/2)
	usedChars := 0
	for scanner.Scan() {
		if lineNum >= endIdx {
			break
		}
		if lineNum >= startIdx {
			lineBudget := maxLineChars
			if returnedLines == 0 {
				available := contentBudget - usedChars - len(fmt.Sprintf("%6d\t\n", lineNum+1))
				lineBudget = min(lineBudget, max(available, 0))
			}
			lineText, wasLineTruncated := common.TruncateRunes(scanner.Text(), lineBudget, "… [line truncated]")
			lineTruncated = lineTruncated || wasLineTruncated
			formatted := fmt.Sprintf("%6d\t%s\n", lineNum+1, lineText)
			if !common.AppendWithinRuneBudget(&sb, &usedChars, formatted, contentBudget) {
				outputTruncated = true
				nextOffset = lineNum + 1
				break
			}
			returnedLines++
		}
		lineNum++
	}
	if err := scanner.Err(); err != nil {
		// bufio.Scanner default token limit is 64KB per line.
		// Binary files, minified JS, or data files often have no newlines and
		// exceed this limit. Return an actionable error instead of empty output.
		msg := fmt.Sprintf(
			"cannot read %s as text: a line exceeds 64KB (likely binary, minified, or single-line data file).\n"+
				"- Binary files: use the analyze tool to inspect structure\n"+
				"- Minified/concatenated code: use download to get the raw file\n"+
				"- Large single-line data: use grep to search for specific content\n"+
				"(scanner error: %v)",
			filepath.Base(input.FilePath), err,
		)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
			IsError: true,
		}, ReadOutput{}, nil
	}

	if nextOffset == 0 && endIdx < totalLines {
		nextOffset = endIdx + 1
	}
	truncated := outputTruncated || endIdx < totalLines || lineTruncated

	// Add file hash only when requested. It is useful with edit.expected_hash,
	// but callers can disable it when reading many short-lived files.
	var fileHash string
	if includeHash && encInfo.RawSize <= readHashThreshold {
		fileHash = encInfo.RawSHA256
	}

	if warning := common.EncodingWarning(encInfo); warning != "" {
		sb.WriteString(warning)
	}
	firstLine, lastLine := startIdx+1, startIdx+returnedLines
	if returnedLines == 0 {
		firstLine, lastLine = 0, 0
	}
	footer := fmt.Sprintf("\n[read: lines=%d-%d/%d; returned=%d; truncated=%t; encoding=%s",
		firstLine, lastLine, totalLines, returnedLines, truncated, encInfo.Charset)
	if nextOffset > 0 {
		footer += fmt.Sprintf("; next_offset=%d", nextOffset)
	}
	if lineTruncated {
		footer += "; line_truncated=true; raise max_line_chars to inspect full long lines"
	}
	if fileHash != "" {
		footer += fmt.Sprintf("; sha256=%s", fileHash)
	}
	footer += "]"
	sb.WriteString(footer)
	marker := "\n[truncated=true; raise max_output_chars or max_line_chars]"
	if nextOffset > 0 {
		marker = fmt.Sprintf("\n[truncated=true; next_offset=%d]", nextOffset)
	}
	result, finalTruncated := common.TruncateRunes(sb.String(), maxOutputChars, marker)
	truncated = truncated || finalTruncated

	out := ReadOutput{
		Content:       result,
		Encoding:      encInfo.Charset,
		TotalLines:    totalLines,
		Hash:          fileHash,
		ReturnedLines: returnedLines,
		Truncated:     truncated,
		NextOffset:    nextOffset,
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, out, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name:        "read",
		Description: `Read text with line numbers or return raster images as ImageContent. Detects common encodings; SVG stays text. Text is bounded and reports truncation/next_offset. Use offset/limit to page; relative paths use the workspace or MCP root.`,
	}, Handle)
}

func handleImage(path string, fi os.FileInfo, mime string) (*mcp.CallToolResult, ReadOutput, error) {
	if fi.Size() > maxImageSize {
		return errorResult(fmt.Sprintf("image too large (%d bytes, max %d). Downscale it first (e.g. with bash)", fi.Size(), maxImageSize))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read image: %v", err))
	}
	// SVG is text-based, return as text instead of binary image
	if mime == "image/svg+xml" {
		text := string(data)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: text}},
		}, ReadOutput{Content: text, Encoding: "utf-8", TotalLines: common.TextLineCount(text)}, nil
	}
	msg := fmt.Sprintf("Image: %s (%d bytes)", filepath.Base(path), fi.Size())
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.ImageContent{Data: data, MIMEType: mime},
			&mcp.TextContent{Text: msg},
		},
	}, ReadOutput{Content: msg, Encoding: "binary"}, nil
}

func errorResult(msg string) (*mcp.CallToolResult, ReadOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ReadOutput{}, nil
}
