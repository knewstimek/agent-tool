package convertenc

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

type ConvertInput struct {
	FilePath   string `json:"file_path" jsonschema:"Absolute path to the file to convert"`
	ToEncoding string `json:"to_encoding" jsonschema:"Target encoding. Examples: UTF-8, UTF-8-BOM, EUC-KR, Shift_JIS, ISO-8859-1"`
}

type ConvertOutput struct {
	Result string `json:"result"`
}

// Handle은 파일의 인코딩을 변환한다.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input ConvertInput) (*mcp.CallToolResult, ConvertOutput, error) {
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}
	if input.ToEncoding == "" {
		return errorResult("to_encoding is required")
	}

	// 대상 인코딩 파싱
	targetCharset, targetBOM := parseTargetEncoding(input.ToEncoding)
	if targetCharset == "" {
		return errorResult(fmt.Sprintf("unsupported encoding: %s\nSupported: UTF-8, UTF-8-BOM, EUC-KR, Shift_JIS, ISO-8859-1, UTF-16BE, UTF-16LE, ASCII, Windows-1252, Big5, GB18030", input.ToEncoding))
	}

	// 파일 존재 확인
	fi, err := os.Stat(input.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", input.FilePath))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}
	if fi.IsDir() {
		return errorResult("path is a directory, not a file")
	}

	// 원본 파일 읽기 (현재 인코딩 자동 감지)
	hintCharset := edit.FindEditorConfigCharset(input.FilePath)
	content, srcInfo, err := common.ReadFileWithEncoding(input.FilePath, hintCharset)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to read file: %v", err))
	}

	// 이미 같은 인코딩이면 스킵
	if srcInfo.Charset == targetCharset && srcInfo.HasBOM == targetBOM {
		msg := fmt.Sprintf("File is already %s, no conversion needed", formatEncName(targetCharset, targetBOM))
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, ConvertOutput{Result: msg}, nil
	}

	// 대상 인코딩으로 쓰기
	dstInfo := common.EncodingInfo{
		Charset: targetCharset,
		HasBOM:  targetBOM,
	}

	srcName := formatEncName(srcInfo.Charset, srcInfo.HasBOM)
	dstName := formatEncName(targetCharset, targetBOM)

	if err := common.WriteFileWithEncoding(input.FilePath, content, dstInfo); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "rune not supported") {
			return errorResult(fmt.Sprintf("conversion failed: file contains characters that cannot be represented in %s (e.g. special Unicode symbols like em-dash, emoji). Remove or replace unsupported characters first.", dstName))
		}
		return errorResult(fmt.Sprintf("failed to write file: %v", err))
	}
	msg := fmt.Sprintf("OK: converted %s → %s (%s)", srcName, dstName, input.FilePath)

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, ConvertOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "convert_encoding",
		Description: `Converts a file's encoding to a different character set.
Reads the file with auto-detected encoding, then rewrites it in the target encoding.
Supports: UTF-8, UTF-8-BOM, EUC-KR, Shift_JIS, ISO-8859-1, UTF-16, ASCII, Windows-1252, Big5, GB18030.
Example: convert EUC-KR file to UTF-8, or add/remove UTF-8 BOM.`,
	}, Handle)
}

// parseTargetEncoding은 사용자 입력을 (charset, hasBOM) 쌍으로 파싱한다.
func parseTargetEncoding(s string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(s))
	switch lower {
	case "utf-8", "utf8":
		return "UTF-8", false
	case "utf-8-bom", "utf8-bom", "utf-8 bom":
		return "UTF-8", true
	case "euc-kr", "euckr":
		return "EUC-KR", false
	case "shift_jis", "shift-jis", "shiftjis", "sjis":
		return "Shift_JIS", false
	case "iso-8859-1", "latin1":
		return "ISO-8859-1", false
	case "utf-16be":
		return "UTF-16BE", false
	case "utf-16le":
		return "UTF-16LE", false
	case "ascii", "us-ascii":
		return "US-ASCII", false
	case "windows-1252", "cp1252":
		return "Windows-1252", false
	case "big5":
		return "Big5", false
	case "gb2312", "gbk", "gb18030":
		return "GB18030", false
	default:
		return "", false
	}
}

func formatEncName(charset string, hasBOM bool) string {
	if charset == "UTF-8" && hasBOM {
		return "UTF-8-BOM"
	}
	return charset
}

func errorResult(msg string) (*mcp.CallToolResult, ConvertOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ConvertOutput{Result: msg}, nil
}
