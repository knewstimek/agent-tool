package config

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ConfigInput struct {
	FallbackEncoding string `json:"fallback_encoding" jsonschema:"description=Set the fallback encoding for files when auto-detection fails. Examples: EUC-KR, Shift_JIS, ISO-8859-1. Empty = no change"`
	EncodingWarnings *bool  `json:"encoding_warnings" jsonschema:"description=Enable/disable encoding detection warning messages in tool results. Default: true"`
	MaxFileSizeMB    *int   `json:"max_file_size_mb" jsonschema:"description=Maximum file size in MB that read/edit/grep tools will accept. Min: 1, Default: 50"`
	AllowSymlinks    *bool  `json:"allow_symlinks" jsonschema:"description=Allow creating symlinks when extracting archives. Default: false (skipped for security)"`
}

type ConfigOutput struct {
	Result string `json:"result"`
}

// Handle은 런타임에 agent-tool 설정을 변경한다.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input ConfigInput) (*mcp.CallToolResult, ConfigOutput, error) {
	changes := []string{}

	// fallback_encoding 처리
	if input.FallbackEncoding != "" {
		normalized := NormalizeAndValidate(input.FallbackEncoding)
		if normalized == "" {
			msg := fmt.Sprintf("Unknown encoding: %s\nSupported: UTF-8, EUC-KR, Shift_JIS, ISO-8859-1, UTF-16BE, UTF-16LE, ASCII, Windows-1252, Big5, GB18030", input.FallbackEncoding)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: msg}},
				IsError: true,
			}, ConfigOutput{Result: msg}, nil
		}
		old := common.GetFallbackEncoding()
		common.SetFallbackEncoding(normalized)
		changes = append(changes, fmt.Sprintf("fallback_encoding: %s → %s", old, normalized))
	}

	// encoding_warnings 처리
	if input.EncodingWarnings != nil {
		old := common.GetEncodingWarnings()
		common.SetEncodingWarnings(*input.EncodingWarnings)
		changes = append(changes, fmt.Sprintf("encoding_warnings: %v → %v", old, *input.EncodingWarnings))
	}

	// max_file_size_mb 처리
	if input.MaxFileSizeMB != nil {
		mb := *input.MaxFileSizeMB
		if mb < 1 {
			mb = 1
		}
		oldMB := common.GetMaxFileSize() / (1024 * 1024)
		common.SetMaxFileSize(int64(mb) * 1024 * 1024)
		changes = append(changes, fmt.Sprintf("max_file_size_mb: %d → %d", oldMB, mb))
	}

	// allow_symlinks 처리
	if input.AllowSymlinks != nil {
		old := common.GetAllowSymlinks()
		common.SetAllowSymlinks(*input.AllowSymlinks)
		note := fmt.Sprintf("allow_symlinks: %v → %v", old, *input.AllowSymlinks)
		if *input.AllowSymlinks {
			note += " ⚠ SECURITY: symlink extraction enabled (tar only). Symlinks targeting outside the output directory are still blocked."
		}
		changes = append(changes, note)
	}

	// 변경 사항 없으면 현재 설정 표시
	if len(changes) == 0 {
		msg := fmt.Sprintf("Current configuration:\n- fallback_encoding: %s\n- encoding_warnings: %v\n- max_file_size_mb: %d\n- allow_symlinks: %v",
			common.GetFallbackEncoding(), common.GetEncodingWarnings(), common.GetMaxFileSize()/(1024*1024), common.GetAllowSymlinks())
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, ConfigOutput{Result: msg}, nil
	}

	msg := "OK: " + strings.Join(changes, ", ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, ConfigOutput{Result: msg}, nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "set_config",
		Description: `Changes agent-tool runtime configuration.
Supports: fallback_encoding, encoding_warnings, max_file_size_mb, allow_symlinks.
Call with no arguments to view current configuration.
Example: set fallback_encoding to "EUC-KR" for Korean legacy projects.`,
	}, Handle)
}

// NormalizeAndValidate는 인코딩 이름을 정규화하고 지원 여부를 확인한다.
// 지원하지 않는 이름은 빈 문자열을 반환한다.
func NormalizeAndValidate(name string) string {
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
