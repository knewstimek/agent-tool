package help

import (
	"context"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type HelpInput struct {
	Topic string `json:"topic" jsonschema:"description=Help topic. Available: overview, encoding, indentation, tools, troubleshooting. Empty = overview"`
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
- Fallback encoding: ` + common.FallbackEncoding + `

## Available Tools
- edit: String replacement with smart indentation + encoding preservation
- read: Encoding-aware file reading with line range support
- write: Encoding-aware file creation/overwrite
- grep: Encoding-aware regex content search
- glob: File pattern matching with ** recursive support
- listdir: Tree-style directory listing
- compress: Create zip / tar.gz archives
- decompress: Extract zip / tar.gz archives
- backup: Timestamped zip backup with exclude patterns
- convert_encoding: Convert file encoding (EUC-KR ↔ UTF-8, BOM, etc.)
- set_config: Change runtime settings (fallback encoding)
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
3. Fallback encoding (currently: ` + common.FallbackEncoding + `)

## Setting up for non-UTF-8 projects

### Option 1: .editorconfig (recommended)
Add to your project's .editorconfig:
  [*]
  charset = euc-kr

This is the most reliable method. The charset value is used directly without auto-detection.

### Option 2: Fallback encoding (server-wide)
Start agent-tool with:
  agent-tool --fallback-encoding EUC-KR

This applies when chardet auto-detection fails (confidence < 50%).

## Supported encodings
UTF-8, UTF-8 BOM, EUC-KR, Shift_JIS, ISO-8859-1, UTF-16BE, UTF-16LE, and more.

## Warning messages
- "Encoding detection failed (low confidence)": chardet couldn't identify the encoding.
  → Add charset to .editorconfig or set --fallback-encoding.
- "Encoding detected as X (confidence: N%)": chardet is unsure about the result.
  → If text looks correct, no action needed. If garbled, add charset to .editorconfig.`
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
Parameters: file_path, old_string, new_string, replace_all, indent_style

## read
Read a file with encoding auto-detection. Returns content with line numbers.
Parameters: file_path, offset (1-based), limit

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
Extract zip or tar.gz archive. Includes Zip Slip protection.
Parameters: archive, output_dir

## backup
Create timestamped zip backup with exclude patterns.
Parameters: source, output_dir, excludes

## convert_encoding
Convert a file's encoding to a different character set.
Supports: UTF-8, UTF-8-BOM, EUC-KR, Shift_JIS, ISO-8859-1, UTF-16, ASCII, Windows-1252, Big5, GB18030.
Parameters: file_path, to_encoding

## set_config
Change agent-tool runtime configuration.
Currently supports: fallback_encoding (used when auto-detection fails).
Call with no arguments to view current config.
Parameters: fallback_encoding`
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
- Fallback encoding: ` + common.FallbackEncoding + `
- This can be changed by restarting agent-tool with --fallback-encoding <CHARSET>`
}
