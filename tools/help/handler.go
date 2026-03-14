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
- prockill: Kill, suspend, or resume processes by PID or port (tree kill, signal selection, zombie handling, dry_run)
- procexec: Execute commands as new processes (background, suspended start, timeout)
- envvar: Read environment variables (sensitive values masked)
- firewall: Read firewall rules (iptables/nftables/netsh, read-only)
- ssh: Execute commands on remote servers via SSH (IPv4/IPv6, ProxyJump, session pooling)
- sftp: Transfer files and manage remote filesystems over SSH (upload, download, ls, stat, mkdir, rm, chmod, rename, async transfers)
- bash: Persistent shell sessions with working directory and environment variable retention
- webfetch: Fetch web content as text/Markdown with ECH, DoH, proxy, and SSRF protection
- websearch: Web search via Brave Search or Naver API (requires API key env vars)
- download: Download files from URLs with ECH, DoH, proxy, and SSRF protection
- httpreq: Execute HTTP requests with any method (POST, PUT, DELETE, etc.) for API testing
- jsonquery: Query JSON files with dot-notation paths to extract specific values (saves tokens)
- portcheck: Check if a TCP port is open on a host (connectivity test)
- externalip: Get your external (public) IP address
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
Use relative_paths=true to return paths relative to search directory (saves tokens).
Parameters: pattern, path, relative_paths

## listdir
List directory in tree format.
Use relative_paths=true to show root as '.' instead of full absolute path (saves tokens).
Parameters: path, max_depth, relative_paths

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
Use dry_run=true to preview: shows included/excluded file counts, directory stats,
exclude pattern match counts, and largest files — without creating the archive.
Parameters: source, output_dir, excludes, dry_run

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

## prockill
Kill, suspend, or resume a process by PID or port number.
Supports tree kill (process + all children), signal selection (kill/term/hup/int/stop/cont).
Use signal=stop to suspend and signal=cont to resume a process.
On Linux, can detect and handle zombie processes by signaling their parent.
Use dry_run=true to preview. Safety: refuses PID 0/1 and self.
Parameters: pid, port, signal, tree, include_zombies, dry_run

## procexec
Execute a command as a new process. Supports foreground, background, and suspended execution.
WARNING: Executes arbitrary commands on the host system.
Use suspended=true to start in suspended state (Windows: CREATE_SUSPENDED, Linux: SIGSTOP).
Use prockill with signal=cont to resume a suspended process.
Parameters: command, args, cwd, env, timeout_sec, background, suspended

## envvar
Read environment variables. Get a specific one by name, or list all with filter.
Sensitive values (PASSWORD, TOKEN, SECRET, KEY, etc.) are automatically masked.
Parameters: name (exact name), filter (partial name match)

## firewall
Read firewall rules (read-only). Supports iptables, nftables, firewalld on Linux; netsh on Windows.
May require elevated privileges (sudo) on Linux.
Parameters: filter (rule name or port)

## ssh
Execute commands on a remote server via SSH. Supports IPv4 and IPv6.
Supports password and key-based authentication. SSH agent auto-used on Unix.
Sessions are pooled and reused (idle timeout: 30 min, max: 20 sessions).
Host key verification: strict (known_hosts required), tofu (trust on first use, default), none (insecure).
ProxyJump: use jump_host to connect through a bastion (e.g. reach IPv6-only servers via IPv4 bastion).
Parameters: host, port, user, password, key_file, passphrase, use_agent, command, disconnect, host_key_check, timeout_sec, jump_host, jump_port, jump_user, jump_password, jump_key_file, jump_passphrase

## sftp
Transfer files and manage remote filesystems over SSH (SFTP protocol).
Reuses SSH session pool — same authentication, session reuse, and idle timeout (30 min) as ssh tool.
Sync operations: upload (local→remote), download (remote→local), ls, stat, mkdir, rm, chmod, rename.
Async operations: upload_async, download_async (returns transfer_id), status (check progress), cancel.
Max transfer size: 2 GB. Recursive delete limited to 10,000 items. Dangerous paths (/, /home, /etc, etc.) protected.
Parameters: host, port, user, password, key_file, passphrase, use_agent, host_key_check,
  jump_host, jump_port, jump_user, jump_password, jump_key_file, jump_passphrase,
  operation, local_path, remote_path, recursive, mode, new_path, overwrite, transfer_id

## bash
Persistent shell sessions that maintain working directory, environment variables, and state across calls.
Sessions are pooled (max 5, idle timeout 30 min). Uses sentinel markers for output delimitation.
Platform: bash/sh on Unix, PowerShell/git-bash/cmd on Windows (auto-detected, best available).
Use disconnect=true to close a session.
Parameters: command, cwd (initial directory for new sessions), session_id (default: "default"), timeout_sec (default 120, max 600), disconnect

## webfetch
Fetch content from a URL and return it as text. HTML pages are automatically converted to Markdown.
ECH (Encrypted Client Hello) and DoH (DNS over HTTPS) enabled by default for privacy.
SSRF protection blocks private/internal IP addresses.
Default User-Agent mimics Chrome browser. Custom headers supported (User-Agent, Referer, etc.).
Supports HTTP and SOCKS5 proxies.
Parameters: url, headers, max_length (default 100000), timeout_sec (default 30, max 120), proxy_url, no_doh, no_ech, raw

## websearch
Search the web using Brave Search or Naver Search API.
Requires API keys via environment variables:
- BRAVE_SEARCH_API_KEY for Brave Search (English/global, default)
- NAVER_CLIENT_ID + NAVER_CLIENT_SECRET for Naver Search (Korean content)
Auto-selects engine based on configured keys (Brave preferred) if engine is not specified.
Parameters: query, engine (brave/naver), max_results (default 5, max 20), timeout_sec (default 15, max 30)

## download
Download a file from a URL and save it to disk. Supports binary and text files.
ECH and DoH enabled by default. SSRF protection. HTTP and SOCKS5 proxy support.
Atomic file write (temp file + rename). Auto-creates parent directories.
Parameters: url, output_path, headers, overwrite, timeout_sec (default 60, max 600), max_size_mb (default 100, max 2048), proxy_url, no_doh, no_ech

## httpreq
Execute HTTP requests with any method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).
Ideal for testing APIs, webhooks, and web services during development.
ECH and DoH enabled by default. SSRF protection. HTTP and SOCKS5 proxy support.
Response body is truncated at max_response_kb. Binary responses show Content-Type and size only.
Parameters: url, method, body, headers, content_type (default application/json), timeout_sec (default 30, max 120), max_response_kb (default 512, max 2048), proxy_url, no_doh, no_ech

## jsonquery
Query a JSON file using dot-notation paths without loading the entire file into context.
Supports nested keys (a.b.c), array indices ([0], [-1] for last), and wildcards ([*] for all elements).
Examples: "dependencies.react", "scripts.build", "items[0].name", "users[*].email".
Returns the matched value with its type. Objects and arrays are pretty-printed.
Parameters: file_path, query

## portcheck
Check if a TCP port is open on a host. Tests connectivity with configurable timeout.
Returns OPEN/CLOSED status with response time or error details (refused, timeout, DNS failure).
Supports hostnames, IPv4, and IPv6 addresses.
Parameters: host, port (1-65535), timeout_sec (default 5, max 30)

## externalip
Returns your external (public) IP address.
Queries multiple IP detection services (ipify, ifconfig.me, icanhazip) with automatic fallback.
Useful for SSH configuration, firewall rules, or verifying VPN/proxy status.
No parameters required.

## set_config
Change agent-tool runtime configuration.
Supports: fallback_encoding, encoding_warnings, max_file_size_mb, allow_symlinks, workspace.
Call with no arguments to view current config.
Parameters: fallback_encoding, encoding_warnings, max_file_size_mb, allow_symlinks, workspace`
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
