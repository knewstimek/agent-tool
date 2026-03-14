package help

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type HelpInput struct {
	Topic string `json:"topic,omitempty" jsonschema:"Help topic. Available: overview, encoding, indentation, tools, troubleshooting. Empty = overview"`
}

type HelpOutput struct {
	Content string `json:"content"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input HelpInput) (*mcp.CallToolResult, HelpOutput, error) {
	topic := strings.ToLower(strings.TrimSpace(input.Topic))
	if topic == "" {
		topic = "overview"
	}

	text := ""
	switch topic {
	case "overview":
		text = helpOverview()
	case "encoding":
		text = helpEncoding()
	case "indentation", "indent":
		text = helpIndentation()
	case "tools":
		text = helpTools()
	case "troubleshooting", "trouble":
		text = helpTroubleshooting()
	default:
		text = "Unknown topic: " + topic + "\n\n" +
			"Available topics: overview, encoding, indentation, tools, troubleshooting"
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, HelpOutput{Content: text}, nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "agent_tool_help",
		Description: `Returns usage guide for agent-tool.
Call this when you encounter encoding warnings, garbled text, or need to understand agent-tool features.
Topics: overview, encoding, indentation, tools, troubleshooting.`,
	}, Handle)
}

func helpOverview() string {
	return `# agent-tool — MCP Tool Server for AI Coding Agents

agent-tool provides encoding-aware and indentation-aware file tools.
It auto-detects file encoding and indentation style, preserving them across edits.

## Current Configuration
- Fallback encoding: ` + common.GetFallbackEncoding() + `

## Available Tools
- edit: String replacement with smart indentation + encoding preservation (supports dry_run)
- read: Encoding-aware file reading with line range support
- write: Encoding-aware file creation/overwrite
- grep: Encoding-aware regex content search
- glob: File pattern matching with ** recursive support
- listdir: Tree-style directory listing
- compress: Create zip / tar.gz archives
- decompress: Extract zip / tar.gz archives
- backup: Timestamped zip backup with exclude patterns
- convert_encoding: Convert file encoding (EUC-KR ↔ UTF-8, BOM, etc.)
- checksum: Compute file hash (md5, sha1, sha256)
- file_info: File metadata (size, encoding, line ending, indentation, line count)
- diff: Compare two files (unified diff output)
- patch: Apply unified diff patch to a file (supports dry_run)
- delete: Delete a single file (no directories, no symlinks, supports dry_run)
- rename: Rename or move a file/directory (atomic, supports dry_run)
- sysinfo: System information (OS, CPU, RAM, disk, uptime, CPU usage measurement)
- find_tools: Discover installed dev tools (compilers, runtimes, build systems)
- proclist: List running processes with PID, name, command line, memory (sensitive args masked)
- envvar: Read environment variables (sensitive values masked)
- firewall: Read firewall rules (iptables/nftables/netsh, read-only)
- set_config: Change runtime settings (fallback encoding, encoding warnings, max file size)
- agent_tool_help: This help tool

## Quick Tips
- Use 'agent_tool_help' with topic='encoding' for encoding setup guide
- Use 'agent_tool_help' with topic='troubleshooting' for common issues`
}

func helpEncoding() string {
	return `# Encoding Guide

## How encoding detection works
Priority order:
1. .editorconfig 'charset' value (highest priority)
2. chardet auto-detection (confidence >= 50%)
3. Fallback encoding (currently: ` + common.GetFallbackEncoding() + `)

## Setting up for non-UTF-8 projects

### Option 1: .editorconfig (recommended)
Add to your project's .editorconfig:
  [*]
  charset = euc-kr

This is the most reliable method. The charset value is used directly without auto-detection.

### Option 2: Environment variable (persistent, no token cost)
Set AGENT_TOOL_FALLBACK_ENCODING environment variable:
  Windows:  setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR
  Linux:    export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR  (add to ~/.bashrc)

### Option 3: CLI flag (per-session)
Start agent-tool with:
  agent-tool --fallback-encoding EUC-KR

Priority: CLI flag > environment variable > default (UTF-8).
These apply when chardet auto-detection fails (confidence < 50%).

## Supported encodings
UTF-8, UTF-8 BOM, EUC-KR, Shift_JIS, ISO-8859-1, UTF-16BE, UTF-16LE, and more.

## Warning messages
- "Encoding detection failed (low confidence)": chardet couldn't identify the encoding.
  → Add charset to .editorconfig or set --fallback-encoding.
- "Encoding detected as X (confidence: N%)": chardet is unsure about the result.
  → If text looks correct, no action needed. If garbled, add charset to .editorconfig.

## Disabling warnings
To suppress encoding warning messages:
  Use set_config with encoding_warnings = false`
}

func helpIndentation() string {
	return `# Indentation Guide

## How indentation detection works
Priority order:
1. .editorconfig 'indent_style' and 'indent_size'
2. File content analysis (first 100 lines)
3. Legacy protection: if .editorconfig says tabs but file uses spaces, spaces are preserved

## Smart indentation conversion
LLMs typically output spaces. agent-tool auto-converts to match the file's style:
- Spaces → Tabs (when file uses tabs)
- Tabs → Spaces (when file uses spaces)
- Spaces 2 → Spaces 4 (different indent sizes)

## Explicit override
The edit tool supports an 'indent_style' parameter:
- "tabs": Force tab indentation
- "spaces-2": Force 2-space indentation
- "spaces-4": Force 4-space indentation
- "spaces": Force 4-space indentation (default size)

## Setting up .editorconfig
  [*]
  indent_style = tab
  indent_size = 4

  [*.py]
  indent_style = space
  indent_size = 4

  [*.{yml,yaml}]
  indent_style = space
  indent_size = 2`
}

func helpTools() string {
	return `# Tool Reference

## edit
Replace text in a file with smart indentation and encoding preservation.
Parameters: file_path, old_string, new_string, replace_all, dry_run, indent_style

## read
Read a file with encoding auto-detection. Returns content with line numbers.
Supports negative offset to read from end (e.g. offset=-5 reads last 5 lines).
Parameters: file_path, offset (1-based, or negative for end-relative), limit

## write
Create or overwrite a file. Preserves encoding for existing files.
Parameters: file_path, content

## grep
Search file contents with regex. Encoding-aware.
Parameters: pattern, path, glob, ignore_case, max_results

## glob
Find files by pattern. Supports ** for recursive matching.
Parameters: pattern, path

## listdir
List directory in tree format.
Parameters: path, max_depth

## compress
Create zip or tar.gz archive.
Parameters: sources (array), output

## decompress
Extract zip or tar.gz archive. Includes Zip Slip and Zip Bomb protection.
Symlinks are skipped by default (security). Enable via set_config allow_symlinks=true.
Even when enabled, symlinks targeting outside the output directory are blocked.
Parameters: archive, output_dir

## backup
Create timestamped zip backup with exclude patterns.
Parameters: source, output_dir, excludes

## convert_encoding
Convert a file's encoding to a different character set.
Supports: UTF-8, UTF-8-BOM, EUC-KR, Shift_JIS, ISO-8859-1, UTF-16, ASCII, Windows-1252, Big5, GB18030.
Parameters: file_path, to_encoding

## checksum
Compute file hash checksum. Reads raw bytes (no encoding conversion).
Parameters: file_path, algorithm (md5, sha1, sha256; default sha256)

## file_info
Returns detailed file metadata: size, encoding, line ending, indentation, line count.
Parameters: file_path

## diff
Compare two files and output unified diff. Encoding-aware.
Parameters: file_a, file_b, context_lines (default 3)

## patch
Apply unified diff patch to a file. Verifies context lines before applying.
Parameters: file_path, patch, dry_run

## delete
Delete a single file safely.
Safety: no directory deletion, no symlinks, no path traversal (..).
Use dry_run=true to preview what would be deleted.
Parameters: file_path, dry_run

## rename
Rename or move a file/directory. Uses os.Rename (atomic operation).
Fails if destination already exists.
Use dry_run=true to preview.
Parameters: old_path, new_path, dry_run

## sysinfo
Returns system information: OS, CPU cores, RAM, disk space, hostname, uptime.
Set duration_sec (1-20) to measure CPU usage over that period.
Parameters: duration_sec

## find_tools
Discover installed development tools on the system.
Returns paths and versions for compilers, build systems, and runtimes.
Searches env vars, PATH, and known installation directories.
Windows: also checks ~/bin, scoop shims, npm global. Unix: also checks ~/bin, ~/.local/bin, Homebrew.
Parameters: category (go, dotnet, node, python, java, rust, c_cpp, build, vcs, container, js_runtime, or all)

## proclist
List running processes with PID, name, command line arguments, and memory usage.
Sensitive data in command lines (passwords, tokens, Bearer) is automatically masked.
Parameters: filter (name search), port (find process using specific port)

## envvar
Read environment variables. Get a specific one by name, or list all with filter.
Sensitive values (PASSWORD, TOKEN, SECRET, KEY, etc.) are automatically masked.
Parameters: name (exact name), filter (partial name match)

## firewall
Read firewall rules (read-only). Supports iptables, nftables, firewalld on Linux; netsh on Windows.
May require elevated privileges (sudo) on Linux.
Parameters: filter (rule name or port)

## set_config
Change agent-tool runtime configuration.
Supports: fallback_encoding, encoding_warnings, max_file_size_mb, allow_symlinks.
Call with no arguments to view current config.
Parameters: fallback_encoding, encoding_warnings, max_file_size_mb, allow_symlinks`
}

func helpTroubleshooting() string {
	return `# Troubleshooting

## Garbled text / encoding issues
Symptom: Korean, Japanese, or other non-ASCII text appears as garbage characters.

Cause: The file is encoded in EUC-KR, Shift-JIS, etc., but chardet couldn't detect it
(common with short files or files with little non-ASCII content).

Solutions (pick one):
1. Add to .editorconfig:
   [*]
   charset = euc-kr

2. Restart agent-tool with --fallback-encoding:
   agent-tool --fallback-encoding EUC-KR

## Indentation mismatch
Symptom: File uses tabs but edit introduces spaces (or vice versa).

Solutions:
1. Add .editorconfig with indent_style = tab
2. Use the edit tool's indent_style parameter: "tabs" or "spaces-4"

## old_string not found
Cause: The text you're trying to match doesn't exist exactly in the file.
Common reasons:
- Indentation differs (tabs vs spaces) — agent-tool handles this automatically
- Line endings differ (CRLF vs LF) — agent-tool normalizes these
- Invisible characters or encoding differences
- The text was already changed

## File encoding changed after edit
This shouldn't happen — agent-tool preserves the original encoding.
If it does, check:
1. Is .editorconfig charset set correctly?
2. Was the file originally in the expected encoding?
3. Report as a bug if encoding changes unexpectedly.

## Current server configuration
- Fallback encoding: ` + common.GetFallbackEncoding() + `
- Encoding warnings: ` + fmt.Sprintf("%v", common.GetEncodingWarnings()) + `
- Max file size: ` + fmt.Sprintf("%d MB", common.GetMaxFileSize()/(1024*1024)) + `
- Allow symlinks: ` + fmt.Sprintf("%v", common.GetAllowSymlinks()) + `
- Use set_config to change at runtime, or --fallback-encoding <CHARSET> at startup`
}
