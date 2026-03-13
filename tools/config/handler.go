package config

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ConfigInput struct {
	FallbackEncoding string `json:"fallback_encoding" jsonschema:"description=Set the fallback encoding for files when auto-detection fails. Examples: EUC-KR, Shift_JIS, ISO-8859-1. Empty = show current config"`
}

type ConfigOutput struct {
	Result string `json:"result"`
}

// Handle은 런타임에 agent-tool 설정을 변경한다.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input ConfigInput) (*mcp.CallToolResult, ConfigOutput, error) {
	if input.FallbackEncoding == "" {
		// 현재 설정 표시
		msg := fmt.Sprintf("Current configuration:\n- fallback_encoding: %s", common.FallbackEncoding)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, ConfigOutput{Result: msg}, nil
	}

	// 인코딩 이름 유효성 검증
	normalized := normalizeAndValidate(input.FallbackEncoding)
	if normalized == "" {
		msg := fmt.Sprintf("Unknown encoding: %s\nSupported: UTF-8, EUC-KR, Shift_JIS, ISO-8859-1, UTF-16BE, UTF-16LE", input.FallbackEncoding)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
			IsError: true,
		}, ConfigOutput{Result: msg}, nil
	}

	old := common.FallbackEncoding
	common.FallbackEncoding = normalized

	msg := fmt.Sprintf("OK: fallback_encoding changed: %s → %s\nThis affects all subsequent file reads where auto-detection fails.", old, normalized)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, ConfigOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "set_config",
		Description: `Changes agent-tool runtime configuration.
Currently supports: fallback_encoding (used when encoding auto-detection fails).
Call with no arguments to view current configuration.
Example: set fallback_encoding to "EUC-KR" for Korean legacy projects.`,
	}, Handle)
}

// normalizeAndValidate는 인코딩 이름을 정규화하고 지원 여부를 확인한다.
func normalizeAndValidate(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case "utf-8", "utf8":
		return "UTF-8"
	case "euc-kr", "euckr":
		return "EUC-KR"
	case "shift_jis", "shift-jis", "shiftjis", "sjis":
		return "Shift_JIS"
	case "iso-8859-1", "latin1":
		return "ISO-8859-1"
	case "utf-16be":
		return "UTF-16BE"
	case "utf-16le":
		return "UTF-16LE"
	case "ascii":
		return "US-ASCII"
	case "windows-1252", "cp1252":
		return "Windows-1252"
	case "big5":
		return "Big5"
	case "gb2312", "gbk", "gb18030":
		return "GB18030"
	default:
		return ""
	}
}
