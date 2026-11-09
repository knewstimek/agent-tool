package multiread

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// readHashThreshold is the maximum file size for automatically including a hash.
const readHashThreshold = 10 * 1024 * 1024 // 10MB

// maxFiles prevents abuse by limiting the number of files per request.
const maxFiles = 50

// maxTotalBytes caps total memory consumption across all files in a single request.
const maxTotalBytes int64 = 100 * 1024 * 1024 // 100MB

// fileEntry holds per-file read parameters resolved from input.
type fileEntry struct {
	Encoding      string
	Path          string
	Offset        int
	Limit         int
	LimitProvided bool
}

// FileRange specifies per-file read range. Used in the "files" parameter.
type FileRange struct {
	Encoding string `json:"encoding,omitempty" jsonschema:"Per-file charset override; otherwise inherits global encoding; BOM takes priority"`
	Path     string `json:"path" jsonschema:"Absolute or workspace-relative file path"`
	Offset   *int   `json:"offset,omitempty" jsonschema:"Line offset (1-based, negative = from end). Default: 1"`
	Limit    *int   `json:"limit,omitempty" jsonschema:"Max lines to read. Default: 200. Set 0 to remove the line limit"`
}

type MultiReadInput struct {
	StartFileIndex int    `json:"start_file_index,omitempty" jsonschema:"Resume at this 1-based index in the original file list; default 1"`
	ResumeOffset   *int   `json:"resume_offset,omitempty" jsonschema:"Override offset only for start_file_index; other files retain their original ranges"`
	Encoding       string `json:"encoding,omitempty" jsonschema:"Default charset override, e.g. EUC-KR or CP949; files entries may override it; BOM takes priority"`
	// Simple mode: list of paths, all using the same offset/limit.
	// Both "file_paths" and "paths" are accepted (alias for compatibility).
	FilePaths      []string `json:"file_paths,omitempty" jsonschema:"File paths to read. All files use the global offset/limit. Use files for per-file ranges"`
	Paths          []string `json:"paths,omitempty" jsonschema:"Compatibility alias for file_paths; prefer file_paths"`
	Offset         *int     `json:"offset,omitempty" jsonschema:"Line number to start from (1-based, negative = from end). Default: 1"`
	Limit          *int     `json:"limit,omitempty" jsonschema:"Maximum lines per file. Default: 200. Set 0 or all=true to remove the line limit"`
	All            bool     `json:"all,omitempty" jsonschema:"Remove the default per-file line limit. The total character budget still applies. Default: false"`
	MaxOutputChars int      `json:"max_output_chars,omitempty" jsonschema:"Maximum total returned text characters across all files. Default: 32768, Min: 256, Max: 131072"`
	MaxLineChars   int      `json:"max_line_chars,omitempty" jsonschema:"Maximum characters returned from one line. Default: 4000, Max: 32768"`
	IncludeHash    bool     `json:"include_hash,omitempty" jsonschema:"Include per-file SHA-256 hashes. Default: false"`

	// Advanced mode: per-file offset/limit. Takes priority over file_paths if both are provided
	Files []FileRange `json:"files,omitempty" jsonschema:"Per-file read ranges. Each entry has path, offset, limit. Takes priority over file_paths"`
}

// resolveEntries converts input to a unified list of fileEntry.
// Returns entries and a validation error string (non-empty means invalid input).
func resolveEntries(input MultiReadInput) ([]fileEntry, string) {
	globalOffset := 0
	if input.Offset != nil {
		globalOffset = *input.Offset
	}
	globalLimit := 0
	globalLimitProvided := input.Limit != nil
	if globalLimitProvided {
		globalLimit = *input.Limit
		if globalLimit < 0 {
			return nil, "limit must be non-negative"
		}
	} else if !input.All {
		globalLimit = 200
	}

	// Merge "paths" alias into file_paths
	if len(input.Paths) > 0 && len(input.FilePaths) == 0 {
		input.FilePaths = input.Paths
	}

	// "files" takes priority
	if len(input.Files) > 0 {
		entries := make([]fileEntry, len(input.Files))
		for i, f := range input.Files {
			off := globalOffset
			if f.Offset != nil {
				off = *f.Offset
			}
			lim := globalLimit
			provided := globalLimitProvided
			if f.Limit != nil {
				lim = *f.Limit
				provided = true
				if lim < 0 {
					return nil, fmt.Sprintf("files[%d].limit must be non-negative", i)
				}
			}
			charset := strings.TrimSpace(f.Encoding)
			if charset == "" {
				charset = strings.TrimSpace(input.Encoding)
			}
			entries[i] = fileEntry{Path: f.Path, Offset: off, Limit: lim, LimitProvided: provided, Encoding: charset}
		}
		return entries, ""
	}
	// Fallback to file_paths with global offset/limit
	entries := make([]fileEntry, len(input.FilePaths))
	for i, p := range input.FilePaths {
		entries[i] = fileEntry{Path: p, Offset: globalOffset, Limit: globalLimit, LimitProvided: globalLimitProvided, Encoding: strings.TrimSpace(input.Encoding)}
	}
	return entries, ""
}

type MultiReadOutput struct {
	Content       string `json:"content"`
	FilesRead     int    `json:"files_read"`
	ErrorCount    int    `json:"error_count"`
	Truncated     bool   `json:"truncated"`
	NextFileIndex int    `json:"next_file_index,omitempty"`
	NextOffset    int    `json:"next_offset,omitempty"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input MultiReadInput) (*mcp.CallToolResult, MultiReadOutput, error) {
	entries, validErr := resolveEntries(input)
	if validErr != "" {
		return errorResult(validErr)
	}
	if len(entries) == 0 {
		return errorResult("file_paths is required and must not be empty")
	}
	if len(entries) > maxFiles {
		return errorResult(fmt.Sprintf("too many files: %d (maximum %d)", len(entries), maxFiles))
	}
	startFile := max(input.StartFileIndex, 1) - 1
	if input.StartFileIndex < 0 || startFile > len(entries) {
		return errorResult("start_file_index is outside the input file list")
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
		maxLineChars = 4000
	}
	if maxLineChars > common.DefaultOutputChars {
		return errorResult(fmt.Sprintf("max_line_chars must be at most %d", common.DefaultOutputChars))
	}

	var sb strings.Builder
	displayRoot := common.RequestWorkspace(ctx, req)
	displayAliases := common.DirectoryAliasMap(ctx, req, common.LocalAliasScope(ctx, req))
	var errorCount int
	var totalBytesRead int64
	filesRead := 0
	usedChars := 0
	contentBudget := maxOutputChars - min(768, maxOutputChars/2)
	truncated := false
	nextFileIndex := 0
	nextOffset := 0

readLoop:
	for i, entry := range entries {
		if i < startFile {
			continue
		}
		originalOffset := entry.Offset
		resuming := i == startFile && input.ResumeOffset != nil
		if resuming {
			entry.Offset = *input.ResumeOffset
		}
		filePath := entry.Path
		appendError := func(message string) bool {
			errorCount++
			available := contentBudget - usedChars
			if available < 16 {
				truncated = true
				nextFileIndex = i + 1
				nextOffset = 0
				return false
			}
			message, cut := common.TruncateRunes(message, available, "…\n")
			truncated = truncated || cut
			return common.AppendWithinRuneBudget(&sb, &usedChars, message, contentBudget)
		}
		if i > startFile && !common.AppendWithinRuneBudget(&sb, &usedChars, "\n", contentBudget) {
			truncated = true
			nextFileIndex = i + 1
			break
		}

		if filePath == "" {
			if !appendError(fmt.Sprintf("ERROR: file[%d] has an empty path\n", i+1)) {
				break
			}
			continue
		}

		resolvedPath, resolveErr := common.ResolveRequestPath(ctx, req, filePath)
		if resolveErr != nil {
			if !appendError(fmt.Sprintf("ERROR: cannot resolve %s: %v\n", filePath, resolveErr)) {
				break
			}
			continue
		}
		filePath = resolvedPath
		displayPath := common.DisplayPathWithAliases(displayRoot, filePath, displayAliases)

		// Header for each file
		header := fmt.Sprintf("=== %s ===\n", displayPath)
		var headerCut bool
		header, headerCut = common.TruncateRunes(header, max(contentBudget-usedChars-64, 32), "… ===\n")
		truncated = truncated || headerCut
		if !common.AppendWithinRuneBudget(&sb, &usedChars, header, contentBudget) {
			truncated = true
			nextFileIndex = i + 1
			break
		}

		fi, err := os.Stat(filePath)
		if err != nil {
			message := ""
			if os.IsNotExist(err) {
				message = fmt.Sprintf("ERROR: file not found: %s\n", displayPath)
			} else {
				message = fmt.Sprintf("ERROR: cannot access file: %v\n", err)
			}
			if !appendError(message) {
				break
			}
			continue
		}
		if fi.IsDir() {
			if !appendError(fmt.Sprintf("ERROR: path is a directory, not a file: %s\n", displayPath)) {
				break
			}
			continue
		}
		if fi.Size() > common.GetMaxFileSize() {
			if !appendError(fmt.Sprintf("ERROR: file too large (%d bytes); skipped\n", fi.Size())) {
				break
			}
			continue
		}

		// Check total memory budget before reading
		totalBytesRead += fi.Size()
		if totalBytesRead > maxTotalBytes {
			appendError("ERROR: total size limit exceeded (100MB), resume with remaining files\n")
			truncated = true
			nextFileIndex = i + 1
			break
		}

		// .editorconfig charset hint
		hintCharset := entry.Encoding
		if hintCharset == "" {
			hintCharset = edit.FindEditorConfigCharset(filePath)
		}

		// Read with encoding detection
		reader := common.ReadFileWithEncoding
		if input.IncludeHash {
			reader = common.ReadFileWithEncodingHash
		}
		content, encInfo, err := reader(filePath, hintCharset)
		if err != nil {
			if !appendError(fmt.Sprintf("ERROR: failed to read file: %v\n", err)) {
				break
			}
			continue
		}
		filesRead++

		// Match bufio.ScanLines semantics; do not report a phantom line after a
		// final newline.
		totalLines := common.TextLineCount(content)

		// Calculate offset range using per-file values
		var startIdx, endIdx int
		if totalLines == 0 {
			startIdx = 0
		} else if entry.Offset < 0 {
			startIdx = totalLines + entry.Offset
			if startIdx < 0 {
				startIdx = 0
			}
		} else {
			offset := entry.Offset
			if offset < 1 {
				offset = 1
			}
			if offset > totalLines {
				startIdx = totalLines
			} else {
				startIdx = offset - 1
			}
		}

		windowStart := startIdx
		if resuming {
			if originalOffset < 0 {
				windowStart = max(totalLines+originalOffset, 0)
			} else {
				windowStart = min(max(originalOffset-1, 0), totalLines)
			}
		}
		endIdx = totalLines
		if entry.Limit > 0 && entry.Limit < endIdx-windowStart {
			endIdx = windowStart + entry.Limit
		}
		if resuming {
			startIdx = min(max(startIdx, windowStart), endIdx)
		}

		// Format with line numbers
		scanner := bufio.NewScanner(strings.NewReader(content))
		scanner.Buffer(make([]byte, 64*1024), len(content)+1)
		scanner.Split(common.ScanTextLines)
		lineNum := 0
		returnedLines := 0
		lineTruncated := false
		for scanner.Scan() {
			if lineNum >= endIdx {
				break
			}
			if lineNum >= startIdx {
				lineBudget := maxLineChars
				if returnedLines == 0 && i == startFile {
					available := contentBudget - usedChars - len(fmt.Sprintf("%6d\t\n", lineNum+1))
					lineBudget = min(lineBudget, max(available, 0))
				}
				lineText, wasTruncated := common.TruncateRunes(scanner.Text(), lineBudget, "… [line truncated]")
				lineTruncated = lineTruncated || wasTruncated
				formatted := fmt.Sprintf("%6d\t%s\n", lineNum+1, lineText)
				if !common.AppendWithinRuneBudget(&sb, &usedChars, formatted, contentBudget) {
					truncated = true
					nextFileIndex = i + 1
					nextOffset = lineNum + 1
					break readLoop
				}
				returnedLines++
			}
			lineNum++
		}
		if err := scanner.Err(); err != nil {
			if !appendError(fmt.Sprintf("ERROR: scanner failed: %v\n", err)) {
				break
			}
			continue
		}

		// Encoding warning
		if warning := common.EncodingWarning(encInfo); warning != "" {
			common.AppendWithinRuneBudget(&sb, &usedChars, warning, contentBudget)
		}

		// File hash (only for files <= 10MB)
		fileHash := ""
		if input.IncludeHash && encInfo.RawSize <= readHashThreshold {
			fileHash = encInfo.RawSHA256
		}

		fileTruncated := endIdx < totalLines || lineTruncated
		truncated = truncated || fileTruncated
		firstLine, lastLine := startIdx+1, startIdx+returnedLines
		if returnedLines == 0 {
			firstLine, lastLine = 0, 0
		}
		footer := fmt.Sprintf("[file: lines=%d-%d/%d; returned=%d; truncated=%t; encoding=%s",
			firstLine, lastLine, totalLines, returnedLines, fileTruncated, encInfo.Charset)
		if endIdx < totalLines {
			footer += fmt.Sprintf("; next_offset=%d", endIdx+1)
		}
		if lineTruncated {
			footer += "; line_truncated=true"
		}
		if fileHash != "" {
			footer += "; sha256=" + fileHash
		}
		footer += "]\n"
		if !common.AppendWithinRuneBudget(&sb, &usedChars, footer, contentBudget) {
			truncated = true
			// All rows in this requested window were emitted. A missing footer
			// must not turn limit=1 into a continuation over the whole file.
			if i+1 < len(entries) {
				nextFileIndex = i + 2
				nextOffset = 0
			}
			break
		}
	}

	summary := fmt.Sprintf("\n[multiread: files_read=%d/%d; errors=%d; truncated=%t", filesRead, len(entries), errorCount, truncated)
	if nextFileIndex > 0 {
		summary += fmt.Sprintf("; next_file_index=%d", nextFileIndex)
	}
	if nextOffset > 0 {
		summary += fmt.Sprintf("; next_offset=%d", nextOffset)
	}
	summary += "]"
	sb.WriteString(summary)

	result, finalTruncated := common.TruncateRunes(sb.String(), maxOutputChars, "\n[truncated=true; resume the original list with start_file_index and resume_offset]")
	truncated = truncated || finalTruncated

	return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: result}},
		}, MultiReadOutput{
			Content:       result,
			FilesRead:     filesRead,
			ErrorCount:    errorCount,
			Truncated:     truncated,
			NextFileIndex: nextFileIndex,
			NextOffset:    nextOffset,
		}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "multiread",
		Description: `Reads multiple files in a single call to reduce API round-trips.
Encoding-aware: auto-detects each file, with optional global/per-file encoding overrides.
Supports offset/limit for reading specific line ranges.
Defaults to 200 lines per file and 32768 characters total across the call.
Returns visible per-file and overall truncation metadata with continuation positions.
Resume the same input list with start_file_index=next_file_index and resume_offset=next_offset (omit resume_offset when zero).
Use file_paths or paths (string array) with global offset/limit, or files (object array) for per-file offset/limit.
If a file fails, the error is included in output and remaining files continue.
Maximum 50 files per request.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, MultiReadOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, MultiReadOutput{}, nil
}
