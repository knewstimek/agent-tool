package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ConfigInput struct {
	FallbackEncoding string `json:"fallback_encoding,omitempty" jsonschema:"Set the fallback encoding for files when auto-detection fails. Examples: EUC-KR, Shift_JIS, ISO-8859-1. Empty = no change"`
	EncodingWarnings *bool  `json:"encoding_warnings,omitempty" jsonschema:"Enable/disable encoding detection warning messages in tool results. Default: true"`
	MaxFileSizeMB    *int   `json:"max_file_size_mb,omitempty" jsonschema:"Maximum file size in MB that read/edit/grep tools will accept. Min: 1, Default: 50"`
	AllowSymlinks    *bool  `json:"allow_symlinks,omitempty" jsonschema:"Allow creating symlinks when extracting archives. Default: false (skipped for security)"`
	Workspace        string `json:"workspace,omitempty" jsonschema:"Set the default workspace/project root directory. Used by glob when no explicit path is given. Must be an absolute path to an existing directory"`
}

type ConfigOutput struct {
	Result string `json:"result"`
}

// Handle changes agent-tool configuration at runtime.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input ConfigInput) (*mcp.CallToolResult, ConfigOutput, error) {
	changes := []string{}

	// Handle fallback_encoding
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

	// Handle encoding_warnings
	if input.EncodingWarnings != nil {
		old := common.GetEncodingWarnings()
		common.SetEncodingWarnings(*input.EncodingWarnings)
		changes = append(changes, fmt.Sprintf("encoding_warnings: %v → %v", old, *input.EncodingWarnings))
	}

	// Handle max_file_size_mb
	if input.MaxFileSizeMB != nil {
		mb := *input.MaxFileSizeMB
		if mb < 1 {
			mb = 1
		}
		oldMB := common.GetMaxFileSize() / (1024 * 1024)
		common.SetMaxFileSize(int64(mb) * 1024 * 1024)
		changes = append(changes, fmt.Sprintf("max_file_size_mb: %d → %d", oldMB, mb))
	}

	// Handle allow_symlinks
	if input.AllowSymlinks != nil {
		old := common.GetAllowSymlinks()
		common.SetAllowSymlinks(*input.AllowSymlinks)
		note := fmt.Sprintf("allow_symlinks: %v → %v", old, *input.AllowSymlinks)
		if *input.AllowSymlinks {
			note += " ⚠ SECURITY: symlink extraction enabled (tar only). Symlinks targeting outside the output directory are still blocked."
		}
		changes = append(changes, note)
	}

	// Handle workspace
	if input.Workspace != "" {
		ws := filepath.Clean(strings.TrimSpace(input.Workspace))
		if !filepath.IsAbs(ws) {
			msg := "workspace must be an absolute path"
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: msg}},
				IsError: true,
			}, ConfigOutput{Result: msg}, nil
		}
		fi, err := os.Stat(ws)
		if err != nil || !fi.IsDir() {
			msg := fmt.Sprintf("workspace directory not found: %s", ws)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: msg}},
				IsError: true,
			}, ConfigOutput{Result: msg}, nil
		}
		old := common.GetWorkspace()
		if old == "" {
			old = "(not set)"
		}
		common.SetWorkspace(ws)
		changes = append(changes, fmt.Sprintf("workspace: %s → %s", old, ws))
	}

	// If no changes were made, display current configuration
	if len(changes) == 0 {
		wsDisplay := common.GetWorkspace()
		if wsDisplay == "" {
			wsDisplay = "(not set, using cwd)"
		}
		msg := fmt.Sprintf("Current configuration:\n- fallback_encoding: %s\n- encoding_warnings: %v\n- max_file_size_mb: %d\n- allow_symlinks: %v\n- workspace: %s",
			common.GetFallbackEncoding(), common.GetEncodingWarnings(), common.GetMaxFileSize()/(1024*1024), common.GetAllowSymlinks(), wsDisplay)
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
Supports: fallback_encoding, encoding_warnings, max_file_size_mb, allow_symlinks, workspace.
Call with no arguments to view current configuration.
Example: set fallback_encoding to "EUC-KR" for Korean legacy projects.`,
	}, Handle)
}

// NormalizeAndValidate normalizes the encoding name and checks if it is supported.
// Returns an empty string for unsupported names.
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
