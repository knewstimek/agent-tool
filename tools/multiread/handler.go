package multiread

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
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

type MultiReadInput struct {
	FilePaths []string `json:"file_paths" jsonschema:"List of absolute file paths to read,required"`
	Offset    int      `json:"offset,omitempty" jsonschema:"Line number to start reading from (1-based). Negative = from end (e.g. -5 = last 5 lines). Default: 1"`
	Limit     int      `json:"limit,omitempty" jsonschema:"Maximum number of lines to read per file. Default: 0 (all)"`
}

type MultiReadOutput struct {
	Content    string `json:"content"`
	FilesRead  int    `json:"files_read"`
	ErrorCount int    `json:"error_count"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input MultiReadInput) (*mcp.CallToolResult, MultiReadOutput, error) {
	if len(input.FilePaths) == 0 {
		return errorResult("file_paths is required and must not be empty")
	}
	if len(input.FilePaths) > maxFiles {
		return errorResult(fmt.Sprintf("too many files: %d (maximum %d)", len(input.FilePaths), maxFiles))
	}

	var sb strings.Builder
	var errorCount int
	var totalBytesRead int64

	for i, filePath := range input.FilePaths {
		if i > 0 {
			sb.WriteString("\n")
		}

		if filePath == "" {
			sb.WriteString("=== (empty path) ===\n")
			sb.WriteString("ERROR: empty file path\n")
			errorCount++
			continue
		}

		// Normalize path to resolve any ".." components
		filePath = filepath.Clean(filePath)

		if !filepath.IsAbs(filePath) {
			sb.WriteString(fmt.Sprintf("=== %s ===\n", filePath))
			sb.WriteString(fmt.Sprintf("ERROR: path must be absolute: %s\n", filePath))
			errorCount++
			continue
		}

		// Header for each file
		sb.WriteString(fmt.Sprintf("=== %s (%s) ===\n", filepath.Base(filePath), filePath))

		fi, err := os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				sb.WriteString(fmt.Sprintf("ERROR: file not found: %s\n", filePath))
			} else {
				sb.WriteString(fmt.Sprintf("ERROR: cannot access file: %v\n", err))
			}
			errorCount++
			continue
		}
		if fi.IsDir() {
			sb.WriteString(fmt.Sprintf("ERROR: path is a directory, not a file: %s\n", filePath))
			errorCount++
			continue
		}

		// Check total memory budget before reading
		totalBytesRead += fi.Size()
		if totalBytesRead > maxTotalBytes {
			sb.WriteString("ERROR: total size limit exceeded (100MB), skipping remaining files\n")
			errorCount++
			break
		}

		// .editorconfig charset hint
		hintCharset := edit.FindEditorConfigCharset(filePath)

		// Read with encoding detection
		content, encInfo, err := common.ReadFileWithEncoding(filePath, hintCharset)
		if err != nil {
			sb.WriteString(fmt.Sprintf("ERROR: failed to read file: %v\n", err))
			errorCount++
			continue
		}

		// Count total lines
		totalLines := strings.Count(content, "\n") + 1

		// Calculate offset range (same logic as tools/read)
		var startIdx, endIdx int
		if input.Offset < 0 {
			startIdx = totalLines + input.Offset
			if startIdx < 0 {
				startIdx = 0
			}
		} else {
			offset := input.Offset
			if offset < 1 {
				offset = 1
			}
			if offset > totalLines {
				offset = totalLines
			}
			startIdx = offset - 1
		}

		endIdx = totalLines
		if input.Limit > 0 && startIdx+input.Limit < endIdx {
			endIdx = startIdx + input.Limit
		}

		// Format with line numbers
		scanner := bufio.NewScanner(strings.NewReader(content))
		lineNum := 0
		for scanner.Scan() {
			if lineNum >= endIdx {
				break
			}
			if lineNum >= startIdx {
				fmt.Fprintf(&sb, "%6d\t%s\n", lineNum+1, scanner.Text())
			}
			lineNum++
		}

		// Encoding warning
		if warning := common.EncodingWarning(encInfo); warning != "" {
			sb.WriteString(warning)
		}

		// File hash (only for files <= 10MB)
		if fi.Size() <= readHashThreshold {
			if h, err := common.ComputeFileHash(filePath); err == nil {
				fmt.Fprintf(&sb, "\n[sha256: %s]", h)
			}
		}

		// Encoding info
		fmt.Fprintf(&sb, "\n[encoding: %s, lines: %d]", encInfo.Charset, totalLines)
	}

	filesRead := len(input.FilePaths) - errorCount
	summary := fmt.Sprintf("\n\n--- Read %d files (%d errors) ---", filesRead, errorCount)
	sb.WriteString(summary)

	result := sb.String()

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, MultiReadOutput{
		Content:    result,
		FilesRead:  filesRead,
		ErrorCount: errorCount,
	}, nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "multiread",
		Description: `Reads multiple files in a single call to reduce API round-trips.
Encoding-aware: auto-detects file encoding for each file.
Supports offset/limit for reading specific line ranges (applied to all files).
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
