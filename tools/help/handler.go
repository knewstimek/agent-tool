package help

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type HelpInput struct {
	Topic string `json:"topic,omitempty" jsonschema:"Help topic: overview (default), encoding, indentation, tools, debug, analyze, memtool, wintool, codegraph, troubleshooting. tools and analyze return an index; append /section for detail, e.g. analyze/decompile or tools/ssh,sftp"`
}

type HelpOutput struct {
	Content string `json:"content"`
}

// topic is one help document. Text before the first "## " heading is its intro;
// each "## " heading opens a section that can be requested alone as
// "<topic>/<heading>" (a heading "a / b" answers to either name).
type topic struct {
	names []string // names[0] is canonical, the rest are aliases
	doc   func() string
	// indexed topics answer a bare request with the intro plus one summary line
	// per section. A reference that covers many independent tools/operations
	// costs thousands of tokens whole, while the caller needs one part of it.
	indexed bool
}

var topics = []topic{
	{names: []string{"overview"}, doc: helpOverview},
	{names: []string{"encoding"}, doc: helpEncoding},
	{names: []string{"indentation", "indent"}, doc: helpIndentation},
	{names: []string{"tools"}, doc: helpTools, indexed: true},
	{names: []string{"debug", "debugger", "dap"}, doc: helpDebug},
	{names: []string{"analyze", "binary", "disassemble", "pe"}, doc: helpAnalyze, indexed: true},
	{names: []string{"memtool", "memscan", "memory", "scan"}, doc: helpMemtool},
	{names: []string{"wintool", "window", "win", "gui"}, doc: helpWintool},
	{names: []string{"codegraph", "code-graph", "graph", "ast"}, doc: helpCodegraph},
	{names: []string{"troubleshooting", "trouble"}, doc: helpTroubleshooting},
}

type section struct {
	heading string
	body    string
}

func (s section) names() []string {
	names := strings.Split(strings.ToLower(s.heading), " / ")
	for i := range names {
		names[i] = strings.TrimSpace(names[i])
	}
	return names
}

func splitSections(doc string) (intro string, sections []section) {
	parts := strings.Split(doc, "\n## ")
	for _, p := range parts[1:] {
		heading, body, _ := strings.Cut(p, "\n")
		sections = append(sections, section{strings.TrimSpace(heading), strings.Trim(body, "\n")})
	}
	return strings.TrimRight(parts[0], "\n"), sections
}

// render returns the whole document, its index, or the requested sections.
// want is the comma-separated part after "<topic>/", already lowercased.
func render(t topic, want string) string {
	doc := t.doc()
	var wanted []string
	for _, name := range strings.Split(want, ",") {
		if name = strings.TrimSpace(name); name != "" {
			wanted = append(wanted, name)
		}
	}
	if len(wanted) == 0 && !t.indexed {
		return doc
	}

	intro, sections := splitSections(doc)
	var b strings.Builder
	if len(wanted) == 0 {
		b.WriteString(intro)
		b.WriteString("\n\n## Sections\n")
		for _, s := range sections {
			summary, _, _ := strings.Cut(s.body, "\n")
			fmt.Fprintf(&b, "- %s: %s\n", s.heading, summary)
		}
		fmt.Fprintf(&b, "\nFull text of a section: agent_tool_help(topic=\"%[1]s/<section>\"); several at once: topic=\"%[1]s/a,b\".", t.names[0])
		return b.String()
	}

	shown := make([]bool, len(sections))
	var unknown []string
	for _, name := range wanted {
		found := false
		for i, s := range sections {
			if !slices.Contains(s.names(), name) {
				continue
			}
			found = true
			if !shown[i] {
				shown[i] = true
				fmt.Fprintf(&b, "## %s\n%s\n\n", s.heading, s.body)
			}
		}
		if !found {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		var available []string
		for _, s := range sections {
			available = append(available, s.names()...)
		}
		fmt.Fprintf(&b, "No section named %s in topic %q. Available: %s",
			strings.Join(unknown, ", "), t.names[0], strings.Join(available, ", "))
	}
	return strings.TrimRight(b.String(), "\n")
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input HelpInput) (*mcp.CallToolResult, HelpOutput, error) {
	name, want, _ := strings.Cut(strings.ToLower(strings.TrimSpace(input.Topic)), "/")
	if name = strings.TrimSpace(name); name == "" {
		name = "overview"
	}

	var text string
	if i := slices.IndexFunc(topics, func(t topic) bool { return slices.Contains(t.names, name) }); i >= 0 {
		text = render(topics[i], want)
	} else {
		var available []string
		for _, t := range topics {
			available = append(available, t.names[0])
		}
		text = "Unknown topic: " + name + "\n\n" +
			"Available topics: " + strings.Join(available, ", ")
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, HelpOutput{Content: text}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "agent_tool_help",
		Description: `Returns usage guide for agent-tool.
Call this when you encounter encoding warnings, garbled text, or need to understand agent-tool features.
Topics: overview, encoding, indentation, tools, debug, analyze, memtool, wintool, codegraph, troubleshooting.
tools and analyze return a short index; request one part with topic="analyze/decompile" or topic="tools/ssh,sftp".`,
	}, Handle)
}

func helpOverview() string {
	return `# agent-tool -- MCP Tool Server for AI Coding Agents

agent-tool provides encoding-aware and indentation-aware file tools.
It auto-detects file encoding and indentation style, preserving them across edits.
The compact core profile is loaded by default; core-lite exposes only
read/write/edit/grep/toolbox. Append +tool names to a preset for extra startup tools
(--profile core+ssh+copy, AGENT_TOOL_PROFILE, or toolbox operation=profile). Use toolbox operation=describe to
load one non-core tool's instructions/schema, then operation=call to invoke it.
compact=true with tool_operation limits describe to one operation; reuse its
schema_handle to receive only an unchanged acknowledgement.
This gateway works even when a client ignores dynamic tool-list changes.
Relative local paths resolve against an explicit workspace, then the client's MCP root.
read diagnostics, multiread headers and edit/copy path metadata use workspace-relative display; file contents stay unchanged.
SSH/SFTP remote_root sets a reusable remote working directory; see topic='tools'.
directory_alias (through toolbox) registers session-only @name/subpath references for local paths and SSH/SFTP targets.

## Current Configuration
- Fallback encoding: ` + common.GetFallbackEncoding() + `

## Available Tools
- edit: String replacement with smart indentation + encoding preservation (supports dry_run)
- read: Encoding-aware file reading with line range support
- write: Encoding-aware file creation/overwrite
- grep: Encoding-aware regex content search
- glob: File pattern matching with ** recursive support
- listdir: Bounded/pageable directory listing with type, name, and counts-only filters
- convert_encoding: Convert file encoding (EUC-KR/CP949 <-> UTF-8, BOM, GBK/GB18030, etc.)
- checksum: Compute file hash (md5, sha1, sha256)
- file_info: File metadata (size, encoding, mixed line-ending counts, indentation, line count)
- diff: Compare two files (unified diff output)
- patch: Apply unified diff patch to a file (supports dry_run)
- delete: Delete one or up to 100 files/directories with compact batch results (supports dry_run)
- rename: Rename or move a file/directory (atomic, supports dry_run)
- proclist: List running processes with PID, name, command line, memory (sensitive args masked)
- prockill: Kill, suspend, or resume processes by PID or port (tree kill, signal selection, zombie handling, dry_run)
- procexec: Execute commands as new processes; slow runs yield a job_id (wait/status/tail/cancel/list), background, suspended start
- ssh: Execute commands on remote servers via SSH (IPv4/IPv6, ProxyJump, session pooling)
- profile_search: Find named SSH/SFTP, MySQL, Cloudflare, and AWS connections
- ssh_key: Convert local SSH private keys between PPK, PEM, OpenSSH, and PKCS#8
- sftp: Transfer files and manage remote filesystems over SSH (upload, download, ls, stat, mkdir, rm, chmod, rename, async transfers)
- bash: Persistent shell sessions with state retention and raw-retrievable diagnostic compaction
- download: Download files from URLs with ECH, DoH, proxy, and SSRF protection
- httpreq: Execute HTTP requests with any method (POST, PUT, DELETE, etc.) for API testing
- copy: Copy files or directories (recursive, atomic write, permissions preserved, dry_run)
- mkdir: Create directories with optional permission mode (recursive by default)
- multiread: Read multiple files in one call (reduces API round-trips)
- regexreplace: Regex find-and-replace across files or directories (capture groups, encoding-aware, dry_run)
- query: Read one value from a JSON/YAML/TOML file by dot-notation path (format from extension; saves tokens)
- netcheck: Network diagnostics: external_ip, dns (A/AAAA/MX/CNAME/TXT/NS/SOA, DoH), tls (certificate expiry, issuer, SANs, protocol, cipher), port (TCP open/closed)
- mysql: Execute MySQL/MariaDB queries (SELECT -> table format, DML -> affected rows)
- redis: Execute Redis commands (any command, result formatting)
- sloc: Count source lines of code (SLOC) with per-language summary
- debug: Interactive debugger via DAP (breakpoints, stepping, variables, stack traces)
- analyze: Static binary analysis of PE/ELF/Mach-O: decompile to C, disassemble, xref, call graph, headers, strings, saved annotations (topic='analyze' lists all 29 operations)
- set_config: Change runtime settings (encoding, file size, SSRF policy, DoH/ECH toggle)
- directory_alias: Set/list/delete session directory aliases; local workspace or remote connection scope
- agent_tool_help: This help tool
- toolbox: Describe/call any tool through one stable gateway; collect yielded jobs (operation=job); optionally manage direct bindings

## Quick Tips
- Use 'agent_tool_help' with topic='encoding' for encoding setup guide
- Use toolbox(operation='describe', tool='ssh'), then toolbox(operation='call', tool='ssh', arguments={...}) for an SSH task
- Long calls do not block: bash, ssh, sftp, download, analyze, codegraph, and memtool return a job_id after ~15s
  (procexec after yield_after_sec). Keep working, then toolbox(operation='job', job_action='wait', job_id=...)
- Job listing/results/cancel are limited to the originating MCP session, across SSH/ProcExec/toolbox.
- Use 'agent_tool_help' with topic='troubleshooting' for common issues`
}

func helpEncoding() string {
	return `# Encoding Guide

## How encoding detection works
Priority order:
1. BOM (UTF-8, UTF-16LE, UTF-16BE) -- conclusive, checked first
2. Per-call encoding override (read/multiread/edit/multiedit/write/patch/file_info), then inherited .editorconfig 'charset'
3. BOM-less UTF-16 (detected from NUL-byte layout; chardet does not report it)
4. Valid UTF-8 -- verified, not guessed, so it outranks chardet and never warns
5. chardet auto-detection (confidence >= 50%)
6. Fallback encoding (currently: ` + common.GetFallbackEncoding() + `)

## Retry a file without changing project settings
Pass encoding="EUC-KR", encoding="CP949", or encoding="Shift_JIS" to
read/multiread/edit/multiedit/write/patch/file_info. This overrides .editorconfig; an existing BOM still wins.
The same encoding is preserved on edits. For intentional conversion use convert_encoding.
Malformed input and lossy decoding return an error before writes.

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
  The file is not valid UTF-8 either, so this one is real -- short non-UTF-8
  files are the common case, since chardet needs a decent sample.
  -> Add charset to .editorconfig or set --fallback-encoding.
- "Encoding detected as X (confidence: N%)": chardet is unsure about the result.
  -> If text looks correct, no action needed. If garbled, add charset to .editorconfig.

## Disabling warnings
To suppress encoding warning messages:
  Use set_config with encoding_warnings = false`
}

func helpIndentation() string {
	return `# Indentation Guide

## How indentation detection works
Priority order:
1. Inherited .editorconfig indent_style, indent_size and tab_width (including indent_size=tab); ** path patterns supported
2. File content analysis (up to 8 MiB, no fixed line-count cap; LF/CRLF/CR supported)
3. Legacy protection: if .editorconfig says tabs but file uses spaces, spaces are preserved

## Smart indentation conversion
LLMs typically output spaces. agent-tool auto-converts to match the file's style:
- Spaces -> Tabs (when file uses tabs)
- Tabs -> Spaces (when file uses spaces)
- Spaces 2 -> Spaces 4 (different indent sizes)
- The style around the match wins over the file's majority style, so a block
  indented differently from the rest of the file keeps its own style, alignment
  and indented blank lines
- Column alignment inside a line and the interior of multi-line strings/comments
  in new_string are kept as written
- The nesting of old_string must agree with the file. When several depths fit
  equally well, add surrounding lines to old_string or pass indent_style

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

memtool, wintool and codegraph have their own topics; analyze and debug have
longer guides under topic="analyze" and topic="debug".

## edit
Replace text in a file with smart indentation and encoding preservation.
Line-ending aware: old_string matches whether the file uses CRLF or LF, and the
newlines in new_string follow the region being edited. Files mixing CRLF and LF
(a CRLF-era file with later LF-only edits) match in either region and keep the
bytes outside the edit unchanged.
When new_string contains non-ASCII text, the result echoes those words back so
you can check them: a string composed as \uXXXX escapes hides its own typos
(one wrong hex digit is still a valid character), and rendering it as text is
the only way to spot that. U+FFFD in the input is reported as corruption.
Parameters: file_path, old_string, new_string, replace_all, dry_run, indent_style, encoding, expected_hash
The source hash is captured with the text and checked again before saving.

## multiedit
Apply several old_string -> new_string replacements to one file in a single call.
Edits run in order, each seeing the previous result, and the whole batch is
atomic: if one edit fails the file is left untouched. Matching, indentation and
line-ending behavior are identical to edit.
Parameters: file_path, edits (array of old_string/new_string/replace_all), dry_run,
encoding, indent_style, expected_hash. Later edits detect the style of the current batch result.

## read
Read a file with encoding auto-detection. Returns content with line numbers.
Image files (PNG, JPG, GIF, BMP, WebP, TIFF, ICO) are returned as base64 ImageContent.
SVG files are returned as text. Supports negative offset to read from end.
Offset accepts an integer, string range "100-200", or [start, end] integer array.
end_line caps the resolved start, including an explicit offset; past EOF returns no lines.
LF, CRLF and CR are logical line breaks across read, multiread, file_info, grep and patch.
Defaults: 400 lines, max_output_chars=32768, max_line_chars=4000. When output is
incomplete, truncated=true and next_offset identify the exact continuation.
Use all=true to remove the default line limit; the character safety budget remains.
Relative paths use the configured workspace or client MCP root. Hash output can be
disabled with include_hash=false. Hashes describe the same raw bytes as the returned text.
max_output_chars is 256..131072. A first line exceeding the available budget is
visibly shortened, so line-based paging can advance; raise the budget to inspect it in full.
Parameters: file_path, offset, limit, start_line, end_line, all, max_output_chars,
max_line_chars, include_hash, encoding

## write
Create or overwrite a file. Preserves encoding for existing files.
U+FFFD in the content is reported: it means the text was already corrupted
before reaching the tool and the original characters cannot be recovered.
Parameters: file_path, content, encoding

## grep
Search file contents with regex. Encoding-aware.
LF, CRLF and CR are line terminators in every output mode, matching read's
line numbers. End-anchored patterns work with each form, and files_with_matches
does not silently stop at a long line.
Output modes: content (default, matching lines), files_with_matches (paths only), count (match counts).
Context: use before/after/context to include surrounding lines (like grep -B/-A/-C).
Defaults: max_results=100, max_line_chars=4000, max_output_chars=32768.
max_results can be raised to 100000; returned text remains bounded by the line
and total-output budgets. context/before/after accept at most 1000 lines.
When additional output exists, has_more=true and next_cursor continues without
rescanning or repeating matches (cursor paging is unavailable with context lines).
Directory search skips binary files (known extensions plus a NUL-byte content
sniff), hidden/generated directories, and root .gitignore/.ignore matches by default.
Use include_hidden/include_ignored to opt in. Paths are relative by default.
Parameters: pattern, path, glob, ignore_case, max_results, output_mode,
output_format (compact default or classic), context, before, after,
max_line_chars, max_output_chars, cursor, relative_paths, include_hidden, include_ignored

## glob
Find files by glob pattern; ** matches recursively.
Results are sorted and paged with limit/next_cursor; has_more and truncation are never silent. Root
.gitignore/.ignore matches and generated/hidden paths are skipped by default.
Parameters: pattern, path, relative_paths, limit, max_output_chars, cursor,
include_hidden, include_ignored

## listdir
List directory contents with bounded, pageable output.
Defaults: flat=true, max_depth=3, max_entries=500 (maximum 10000).
When has_more=true, pass next_cursor back as cursor to fetch the next page.
Use directories_only or files_only to filter by type (not both).
Use name_pattern for one entry-name glob (for example A* or *.go), or include
for multiple OR glob patterns. Directories are still traversed when their own
names do not match, so matching descendants can be returned.
Use counts_only=true to return matching counts without listing names.
Use flat=false for visual tree structure with connectors.
Use relative_paths=true to show root as '.' instead of full absolute path (saves tokens).
Parameters: path, max_depth, max_entries, cursor, relative_paths, flat,
directories_only, files_only, name_pattern, include (array), counts_only
Returns: tree, returned_files, returned_dirs, total_files, total_dirs,
truncated, has_more, next_cursor

## convert_encoding
Convert a file's encoding to a different character set.
Supports: UTF-8, UTF-8-BOM, EUC-KR, Shift_JIS, ISO-8859-1, UTF-16, ASCII, Windows-1252, Big5, GB18030.
Parameters: file_path, to_encoding, from_encoding (optional source charset override).
GBK is distinct from GB18030; GB2312 is a compatibility alias for GBK.
Unsupported target characters return an error and leave original bytes unchanged.

## checksum
Compute file hash checksum. Reads raw bytes (no encoding conversion).
Parameters: file_path, algorithm (md5, sha1, sha256; default sha256)

## file_info
Returns detailed file metadata: size, encoding, line ending, indentation, line count.
Mixed newlines are reported with separate CRLF, LF, and CR counts.
Parameters: file_path, encoding

## diff
Compare two files and output unified diff. Encoding-aware.
Lines are compared with their endings normalized, so files differing only in
line endings report that explicitly instead of an empty diff.
Parameters: file_a, file_b, encoding_a, encoding_b, context_lines (default 3; 0 for none).
Identical decoded text with different encoding/BOM bytes is reported separately.
CR/LF placement and missing-final-newline differences are distinct.

## patch
Apply unified diff patch to a file. Verifies context lines before applying.
Each line keeps its own ending, so a file mixing CRLF and LF is not rewritten,
and a file without a trailing newline does not gain one. Lines the patch adds
take the ending of the line they replace.
Parameters: file_path, patch, dry_run, encoding, expected_hash

## delete
Delete one file/directory, or up to 100 targets with file_paths.
Do not combine file_paths with file_path/path. Batch output aggregates successes, errors, file
and directory counts, and bytes; at most 10 error details are shown.
Directory deletion requires recursive=true.
Recursive deletion is limited to 10,000 items and 100 directory levels. It
refuses filesystem roots, the workspace root, the user home directory, system
paths, and trees containing symlinks. Errors explain why deletion stopped and
whether a partial deletion may have occurred.
Use dry_run=true with recursive=true to preview file/directory counts and bytes.
Parameters: file_path, file_paths, recursive, dry_run

## rename
Rename or move a file/directory. Uses os.Rename (atomic operation).
Fails if destination already exists.
Use dry_run=true to preview.
Parameters: old_path, new_path, dry_run

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
Execute a command as a new process without blocking the agent for long.
WARNING: Executes arbitrary commands on the host system.
Yielding: a run waits up to yield_after_sec (default 15, max 300). If the process finishes in time
the full result is returned as usual. Otherwise the call returns job_id plus the last output lines
while the process keeps running, so the agent can answer the user or do other work meanwhile.
Job operations (job_id required except list):
  wait    block up to wait_sec (default 30, max 300); returns the final result once finished.
          Cancelling the wait call does not stop the job.
  status  non-blocking snapshot (final result if finished, recent output if running)
  tail    last tail_lines lines per stream (default 20, max 1000). Passing tail_lines to wait/status
          also limits a finished job to its tail (use for progress-refresh output such as watch loops)
  cancel  kill the whole tree via a job object on Windows (also orphaned grandchildren), process group on Unix.
          A requested cancel is not an error; cancelling a finished job returns its result
  list    all jobs; finished jobs are kept for 1 hour, at most 32 running at once
timeout_sec is the hard lifetime limit (default 600, max 7200), not how long the call blocks;
a killed job reports status=timed_out with the output captured so far.
background=true returns job_id immediately, still captures output, and has no implicit time limit
(use it for servers). Jobs do not survive an agent-tool restart.
Use suspended=true to start in suspended state (Windows: CREATE_SUSPENDED, Linux: SIGSTOP),
detached and without output capture. Use prockill with signal=cont to resume it.
Final output compacts repeated diagnostics by default. output_view=raw disables it.
When compacted, retrieve the bounded original for 30 minutes with toolbox operation=output and raw_output_id.
Parameters: operation, command, args, cwd, env, timeout_sec, yield_after_sec, background, suspended,
job_id, wait_sec, tail_lines, max_output_chars, output_view

## ssh
Execute commands on a remote server via SSH. Supports IPv4 and IPv6.
Supports password and key-based authentication (PEM, OpenSSH, and PuTTY PPK formats). SSH agent auto-used on Unix.
Sessions are pooled and reused (idle timeout: 30 min, max: 20 sessions).
Pool identity includes the MCP session, authentication, host-key policy, and ProxyJump settings.
Connection handles and disconnect affect only the calling MCP session.
Host key verification: strict (known_hosts required), tofu (trust on first use, default), none (insecure).
ProxyJump: use jump_host to connect through a bastion (e.g. reach IPv6-only servers via IPv4 bastion).
Foreground output defaults to 32768 bytes with original byte counts. output_mode
selects head_tail (default), head, or tail retention.
For Windows scripts use powershell_script instead of command (UTF-8, max 4 MiB).
Uploads a unique temporary script through SSH stdin, executes it, and cleans up after
success/failure. Long standalone EncodedCommand invocations are staged automatically.
Preparation shares timeout_sec with execution. Unconfirmed remote completion or
deletion is reported separately as cleanup_warning, including for background jobs.
Non-zero remote exits return IsError=true. For long-running commands, use background=true or
	operation=start, then operation=wait/status/tail/cancel with job_id (tail_lines defaults to 50; wait_sec 30, max 300).
	SSH jobs share the job registry, so toolbox operation=job also lists and waits on them.
	powershell_script forces UTF-8 output and silences progress records, so non-English hosts return readable text.
	connection_profile resolves a local profile (find names with profile_search); connection_id reuses its
	connection fields for 30 minutes. remote_root in a profile or first call is also
	retained in connection_id and shared with SFTP. Each command starts in that root;
	failed cwd setup prevents execution. remote_shell: posix (default), cmd (default
	for Windows drive roots), powershell. Windows CMD+remote_root requires PowerShell.
	quiet suppresses banners, echo_command defaults false, and result_only returns
	stdout/stderr/exit_code JSON. stdout/stderr are never rewritten.
	Parameters: operation, background, job_id, tail_lines, host, port, user, password,
	key_file, passphrase, use_agent, command, powershell_script, disconnect, host_key_check, timeout_sec,
	max_output_chars, output_mode, jump_host, jump_port, jump_user, jump_password,
	jump_key_file, jump_passphrase, connection_profile, connection_id, remote_root, remote_shell, quiet, echo_command, result_only

## profile_search
Find named SSH/SFTP, MySQL, Cloudflare, and AWS connections by non-secret profile metadata.
Use kind to filter. Omit query to list. Every word matches part of a name, alias, description, or tag, ignoring case.
Use limit (default 20, max 100) and pass next_offset as offset with the same filters to continue.
Pass connection_profile to ssh, sftp, mysql, or httpreq. For httpreq also pass profile_kind (aws or cloudflare).
Through toolbox: operation=call, tool=profile_search, arguments={"kind":"mysql","query":"reporting"}.
For registration and revision history see tools/credential_vault.

## credential_vault
Register encrypted connection profiles. The default local vault opens automatically.
Run agent-tool vault put KIND NAME --help for connection flags. Secrets are entered without echo.
An optional vault created with vault init --passphrase requires vault unlock before connecting.
Use vault list and vault history KIND NAME to read revisions. Pass --revision N on edits, replacement, and deletion.
Run agent-tool vault import-ssh to copy legacy profiles under new names ending in -vault while keeping the original JSON and keys.
SQLite lives at agent-tool/profiles.sqlite under local app data (Windows) or the user config directory (other systems).
For an automatic vault, keep the matching profiles.sqlite.key file private. It is required to recover a copied database.
For an alternate absolute path set AGENT_TOOL_VAULT_FILE for both AgentTool and the unlock terminal.
Keep aliases, descriptions, and tags free of credentials. Old connections.json files and imported key files still exist on disk.

## ssh_key
Convert a local SSH private-key file between PPK, PEM, PKCS#8 and OpenSSH.
The input format is auto-detected. Output formats: ppk (PuTTY PPK v3), pem (traditional key-specific PEM),
openssh (modern OpenSSH), or pkcs8. RSA, ECDSA, Ed25519, and DSA are supported where
the target format permits them. output_passphrase is supported for ppk and openssh;
legacy encrypted PEM is intentionally not generated. The tool never returns key
material, writes new files with mode 0600, and refuses replacement unless overwrite=true.
Parameters: operation (convert), input_path, output_path, output_format,
  input_passphrase, output_passphrase, comment, overwrite

## sftp
Transfer files and manage remote filesystems over SSH (SFTP protocol).
Reuses SSH session pool -- same authentication, session reuse, and idle timeout (30 min) as ssh tool.
remote_root (from profile, connection_id, or call) anchors relative remote_path,
rename new_path and batch destinations. Generated path metadata is relative to
the local workspace / remote root. Absolute outside paths keep their meaning;
remote_root is a working directory, not a filesystem sandbox.
	Sync operations: upload (local->remote), upload_many (up to 100 files over one session),
	download (remote->local), ls, stat, mkdir, rm, chmod, rename.
Async operations: upload_async, download_async (returns transfer_id), status (check progress), cancel.
Status/cancel is restricted to the originating MCP session; status rechecks current aliases and shows exact remote paths when aliases no longer match.
Max transfer size: 2 GB. Recursive delete limited to 10,000 items. Dangerous paths (/, /home, /etc, etc.) protected.
Parameters: host, port, user, password, key_file, passphrase, use_agent, host_key_check,
  jump_host, jump_port, jump_user, jump_password, jump_key_file, jump_passphrase,
	  operation, local_path, remote_path, uploads, recursive, mode, new_path, overwrite,
	  transfer_id, connection_profile, connection_id, remote_root, remote_shell, quiet, result_only

## bash
Persistent shell sessions that maintain working directory, environment variables, and state across calls.
Sessions are pooled (max 5, idle timeout 30 min). Uses sentinel markers for output delimitation.
session_id, including default, belongs to the calling MCP session. Other clients cannot reuse or disconnect it.
At capacity, only the caller's idle shell can be evicted; otherwise creation fails.
Platform: bash/sh on Unix, pwsh/git-bash/powershell/cmd on Windows (auto-detected, priority order).
Use disconnect=true to close a session.
Output defaults to 32768 bytes and preserves head+tail with explicit truncation metadata.
Repeated diagnostics are compacted by default; output_view=raw disables it. When compacted,
retrieve the bounded original for 30 minutes with toolbox operation=output and raw_output_id.
A command still running after ~15s returns a job_id while it keeps running; collect the result with
toolbox operation=job job_action=wait job_id=<id>. timeout_sec stays the kill limit. A session runs one
command at a time: while its yielded command runs, a new call on that session fails fast with guidance;
use another session_id. For servers or live output, prefer procexec (background=true, operation=tail).
Parameters: command, cwd (initial directory for new sessions), session_id (default: "default"), timeout_sec (default 120, max 600), output_view, disconnect

## download
Download a file from a URL and save it to disk. Supports binary and text files.
ECH and DoH enabled by default. Cloud metadata SSRF protection. HTTP and SOCKS5 proxy support.
Atomic file write (temp file + rename). Auto-creates parent directories.
Parameters: url, output_path, headers, overwrite, timeout_sec (default 60, max 600), max_size_mb (default 100, max 2048), proxy_url, no_doh, no_ech

## httpreq
Execute HTTP requests with any method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).
Vault profiles use connection_profile and profile_kind. Cloudflare uses api.cloudflare.com/client/v4/. AWS uses the profile's fixed HTTPS origin and SigV4. Vault requests do not follow redirects or accept a proxy override.
ECH and DoH enabled by default. Cloud metadata SSRF protection. HTTP and SOCKS5 proxy support.
DLP: POST/PUT/PATCH bodies are scanned for sensitive data (PEM keys, AWS keys, tokens, .env dumps) and blocked before transmission.
Response body is truncated at max_response_kb. Binary responses show Content-Type and size only.
Parameters: url, method, body, headers, content_type (default application/json), timeout_sec (default 30, max 120), max_response_kb (default 32, max 128), proxy_url, no_doh, no_ech

## directory_alias
Register session-only directory shortcuts through toolbox describe/call.
Local set: {"operation":"set","aliases":{"src":"src"}} (directory must exist).
Remote set: add connection_profile or connection_id; values must be absolute.
Use @src/file in common local path arguments, or a remote alias in SSH remote_root
and SFTP path arguments. SSH command text and file contents are never substituted.
list returns mappings only on request (names filters); delete removes names.
Changing existing values requires overwrite=true. No alias files are saved/loaded.
Each call uses one workspace/alias snapshot; concurrent changes affect later calls.
File path whitespace is preserved. Equivalent SSH defaults keep the same alias scope.
Session/workspace/remote-target scopes are separate; names are case-sensitive,
at most 64 aliases per scope. Unknown aliases and .. / rooted / colon suffixes fail.
Use ./@literal for actual names beginning with @. This is not a symlink sandbox.
Parameters: operation, aliases, names, overwrite, connection_profile, connection_id

## copy
Copy a file or directory. Supports recursive directory copying.
Uses atomic write (temp file + rename) and preserves file permissions.
Relative paths use the configured workspace or client MCP root; dangerous paths are blocked.
Parameters: source, destination, overwrite (default false), dry_run (default false)

## mkdir
Create a directory. Creates parent directories by default (like mkdir -p).
Supports permission mode in octal (e.g. 0755, 0700) -- applied on Unix/Linux.
Use dry_run=true to preview what would be created.
Parameters: path, recursive (default true), mode (octal, default 0755), dry_run

## multiread
Read multiple files in a single call to reduce API round-trips.
Each file is read with encoding auto-detection and line numbering.
Files are separated with headers. Errors on individual files don't stop processing.
Defaults: 200 lines per file and 32768 total characters. Per-file and overall
next_offset/next_file_index metadata identify continuation. Hashes are opt-in.
Resume the SAME original input list with start_file_index=next_file_index and
resume_offset=next_offset (omit resume_offset when zero). The resumed offset
applies only within that file's original window; later files retain their original ranges.
Global encoding can be overridden by files entries\' encoding. Existing BOMs win.
Relative paths use the configured workspace or client MCP root.
Parameters: file_paths (array, max 50), files (path/offset/limit/encoding entries),
offset, limit, all, max_output_chars (256..131072), max_line_chars, include_hash,
encoding, start_file_index, resume_offset

## regexreplace
Regex find-and-replace in files or across directories.
Directory work is per-file, not an all-or-nothing transaction. Partial failures
report error_count and bounded ERROR samples; successful changes are retained.
max_files caps matching files, with limit_reached=true when that cap is reached.
Use encoding to override the source charset; retry only failed files after a partial result.
Supports capture groups ($1, $2, ${name}) in replacement strings.
Encoding-aware: preserves original file encoding.
Replacement newlines follow the newline style of the region each match sits in,
so mixed CRLF/LF files are not rewritten. Converting line endings on purpose is
the exception: a pattern that requires a CR ("\r\n") or a replacement containing
one is written verbatim, so CRLF <-> LF conversion works.
The pattern side is matched against decoded text with its newlines intact: use
\r?\n for a line break and (?m) with \r?$ for end-of-line, or a CRLF file will
not match. When nothing matches, the result says how many scanned files use CRLF.
Skips binary files by extension and NUL-byte content sniff, so an on-disk
index or compiled artifact is never rewritten.
Atomic write for each modified file.
Parameters: pattern, replacement, path (file or directory), glob, ignore_case, dry_run,
encoding, max_files (default 100 matching files). Reports files_scanned,
error_count, limit_reached and truncated. ERROR samples are bounded.

## query
Read one value from a JSON, YAML or TOML file by a dot-notation path, without loading the file into context.
Format comes from the extension (.json, .yaml/.yml, .toml); pass format=json|yaml|toml for other names.
Supports nested keys (a.b.c), array indices ([0], [-1] for last), and wildcards ([*] for all elements).
Examples: "scripts.build", "services.web.ports[0]", "tool.poetry.name", "users[*].email".
Returns the value with its type; objects and arrays print as JSON, TOML datetimes as RFC3339.
Parameters: file_path, query, format, max_output_chars

## netcheck
Network diagnostics: external IP, DNS records, TLS certificate and TCP port checks.
One operation per call:
- external_ip: public IPv4 and IPv6 (several detection services with fallback)
- dns: records for host; record_type A, AAAA, MX, CNAME, TXT, NS, SOA (default A);
  DNS over HTTPS by default (use_doh=false for the system resolver, doh_endpoint to override)
- tls: certificate Subject, Issuer, NotBefore/NotAfter, days to expiry, SANs, TLS version, cipher
  for host:port (default 443, timeout_sec default 10, max 30)
- port: whether TCP port on host is OPEN or CLOSED, with response time or the failure
  (refused, timeout, DNS); port required, timeout_sec default 5, max 30
Parameters: operation, host, record_type, use_doh, doh_endpoint, port, timeout_sec

## mysql
Execute SQL queries on a MySQL/MariaDB server.
With connection_profile, omit host, port, user, password, database, and tls.
SELECT/SHOW/DESCRIBE/EXPLAIN queries return results as formatted table.
Other queries (INSERT/UPDATE/DELETE) return affected rows and last insert ID.
Connection is opened and closed per call (no session pooling).
Connections use utf8mb4 for client, connection, and result text.
Set tls=true to use verified TLS 1.2 or newer.
Defaults: max_rows=1000, max_columns=100, max_value_chars=200,
max_output_chars=32768 (max 131072). Use SQL LIMIT/OFFSET for deterministic paging.
Parameters: host, port (default 3306), user, password, database, query,
timeout_sec (default 30, max 120), tls, max_rows, max_columns,
max_value_chars, max_output_chars

## redis
Execute Redis commands on a Redis server.
Supports any Redis command (GET, SET, HGETALL, etc.) via command + args.
Results are formatted by type (string, integer, array, nil).
Supports TLS connections. Connection is opened and closed per call.
TLS certificate verification uses the requested hostname even when SSRF-safe resolution connects to an IP address.
Defaults: max_value_chars=200, max_output_chars=32768 (max 131072).
Parameters: host, port (default 6379), password, db (default 0), command,
args (array), timeout_sec (default 30, max 120), tls, max_value_chars,
max_output_chars

## sloc
Count source lines of code (SLOC) in a file or directory.
Returns per-language summary with file count, total lines, and blank lines.
Recognizes 70+ languages by file extension. Skips node_modules, .git, vendor, dist, build.
Parameters: path (file or directory), glob (filter pattern), max_depth, show_files,
skip_blank, max_output_chars (default 32768, max 131072)

## debug
Interactive debugger using Debug Adapter Protocol (DAP).
Supports any language with a DAP-compatible adapter (dlv for Go, debugpy for Python, codelldb/lldb-dap for C/C++/Rust).
Uses a single tool with operation parameter for all debug actions.
Operations: launch, attach, set_breakpoints, continue, next, step_in, step_out, pause, threads, stack_trace, scopes, variables, evaluate, disconnect, status.
Session-based: launch/attach creates a session, subsequent operations use session_id.
Stepping operations (continue, next, step_in, step_out) block until a stopped event (breakpoint, step completion) or timeout.
Use operation=status to poll for events (output, state changes) between operations.
Parameters: session_id, operation, adapter_command, adapter_args, address, launch_args (JSON),
  source_path, breakpoints (JSON array), thread_id, frame_id, variables_reference,
  expression, context, timeout_sec, start, max_results, max_value_chars,
  max_output_chars, variable_filter, start_module, module_count

## analyze
Static binary analysis of PE/ELF/Mach-O files: decompile to C, disassemble, xref, call graph, headers, strings, user annotations.
Per-operation guide: topic="analyze" (index), then topic="analyze/<operation>".

## set_config
Change agent-tool runtime configuration.
Supports: fallback_encoding, encoding_warnings, max_file_size_mb, allow_symlinks, workspace.
SSRF policy: allow_http_private (default false), allow_mysql_private, allow_redis_private, allow_ssh_private (default true).
Network: enable_doh (DNS over HTTPS, default true), enable_ech (Encrypted Client Hello, default true).
Call with no arguments to view current config.
Parameters: fallback_encoding, encoding_warnings, max_file_size_mb, allow_symlinks, workspace, allow_http_private, allow_mysql_private, allow_redis_private, allow_ssh_private, enable_doh, enable_ech`
}

func helpDebug() string {
	return `# Debug Tool Guide (DAP)

## Overview
The debug tool provides interactive debugging via the Debug Adapter Protocol (DAP).
It works with any language that has a DAP-compatible debug adapter.

## Tested Adapters
- Go: dlv (Delve) -- fully tested
- Python: debugpy -- fully tested
- C/C++: codelldb (recommended, open source) -- LLDB-based, reads PDB on Windows
- C/C++: vsdbg -- UNSTABLE: its license check rejects non-VS Code clients even
  after a successful handshake. Use codelldb unless you need MSVC-native debugging.

## Workflow

### 1. Launch -> 2. Set breakpoints -> 3. Continue -> 4. Inspect -> 5. Step -> 6. Disconnect

  launch -> set_breakpoints -> continue (blocks until hit) ->
  stack_trace -> scopes -> variables -> evaluate ->
  next/step_in/step_out -> continue -> ... -> disconnect

## Adapter Recipes (copy-paste ready)

### Go (dlv)
  Install: go install github.com/go-delve/delve/cmd/dlv@latest

  debug(operation="launch",
        adapter_command="dlv", adapter_args=["dap"],
        launch_args='{"program":"./","mode":"debug","cwd":"/path/to/project"}')

  With registers:
  launch_args='{"program":"./","mode":"debug","cwd":"/path/to/project","showRegisters":true}'

  IMPORTANT: "program" should be "./" (relative) with "cwd" set to the project directory.
  Using an absolute path for "program" may fail if it points to a directory.

### Python (debugpy)
  Install: pip install debugpy

  Stdio mode (recommended -- single step):
  debug(operation="launch",
        adapter_command="python", adapter_args=["-m", "debugpy.adapter"],
        launch_args='{"program":"/path/to/script.py","cwd":"/path/to/project","console":"internalConsole"}')

  TCP mode (alternative -- two steps):
  Step 1: Run in terminal: python -m debugpy.adapter --host 127.0.0.1 --port 5679
  Step 2: debug(operation="attach", address="127.0.0.1:5679",
        launch_args='{"program":"/path/to/script.py","request":"launch","console":"internalConsole"}')

### C/C++ (codelldb -- recommended)
  Install: Download from https://github.com/vadimcn/codelldb/releases
  Or install the CodeLLDB VS Code extension.

  debug(operation="launch",
        adapter_command="/path/to/codelldb",
        adapter_args=["--port", "0"],
        launch_args='{"type":"lldb","program":"/path/to/binary","cwd":"/path/to/project","stopOnEntry":true}')

### C/C++ (vsdbg -- UNSTABLE, requires VS Code C++ extension installed)
  A rejection reading "C/C++ Debugging is supported only in Microsoft versions
  of VS Code" is the license check above; switch to codelldb.

  vsdbg requires adapterID="cppvsdbg" and clientID="vscode".
  Set "type":"cppvsdbg" and "__clientID":"vscode" in launch_args.

  debug(operation="launch",
        adapter_command="/path/to/vsdbg.exe",
        adapter_args=["--interpreter=vscode"],
        launch_args='{"type":"cppvsdbg","__clientID":"vscode","__clientName":"Visual Studio Code","program":"/path/to/binary.exe","cwd":"/path/to/project","console":"internalConsole","stopAtEntry":true}')

  vsdbg is typically located at:
  Windows: %USERPROFILE%/.vscode/extensions/ms-vscode.cpptools-*/debugAdapters/vsdbg/bin/vsdbg.exe
  Linux/Mac: ~/.vscode/extensions/ms-vscode.cpptools-*/debugAdapters/vsdbg/bin/vsdbg

## Key Operations Reference

  Core:
    set_breakpoints: source_path + breakpoints='[{"line":42},{"line":100,"condition":"x > 5"}]'
    continue/next/step_in/step_out: blocks until stopped (timeout_sec to limit wait)
    stack_trace: returns frame IDs -> use frame_id for scopes/evaluate
    scopes: returns scope names + variablesReference IDs -> use for variables
    variables: returns variable names, values, and nested references
    evaluate: expression evaluation with context (repl/watch/hover)
    threads: list all threads/goroutines
    status: session state + recent events (non-blocking)
    disconnect: end session and clean up

  Breakpoints:
    set_function_breakpoints: breakpoints='[{"name":"main.Run"}]'
    set_exception_breakpoints: filters='["raised","uncaught"]'
    set_data_breakpoints: breakpoints='[{"dataId":"...","accessType":"write"}]'
    data_breakpoint_info: query if data breakpoint can be set (name + variables_reference)
    set_instruction_breakpoints: breakpoints='[{"instructionReference":"0x4000"}]'

  Execution control:
    step_back / reverse_continue: reverse debugging (adapter must support)
    restart_frame: restart from a stack frame (frame_id)
    goto: jump to a target (target_id from goto_targets)
    goto_targets: list possible jump targets (source_path + line)
    step_in_targets: list possible step-in targets (frame_id)
    pause: suspend execution
    terminate: graceful termination (debuggee handles it)
    restart: restart the debug session

  Modification:
    set_variable: change variable value (variables_reference + name + value)
    set_expression: change expression value (expression + value + frame_id)

  Memory / disassembly:
    disassemble: disassemble from memory_reference (count = instruction count;
                 show_bytes=true adds the instruction bytes column)
    read_memory: read bytes from memory_reference (count = byte count, returns base64)
    write_memory: write base64 data to memory_reference

  Info:
    modules: loaded modules/libraries (with symbol status)
    resolve_address: map address to module+offset (memory_reference='0x7ffe5488')
    loaded_sources: all loaded source files
    source: get source code by source_reference
    exception_info: current exception details (thread_id)
    completions: auto-completion suggestions (text + frame_id)
    cancel: cancel a pending request (request_id)
    terminate_threads: terminate specific threads (thread_ids='[1,2]')

  Bounded output and paging:
    variables/completions/loaded_sources: start + max_results (default 200, max 10000)
    modules: start_module + module_count (module_count defaults to max_results)
    variable/evaluation values: max_value_chars (default 4000, max 100000)
    all listed operations: max_output_chars (default 32768, max 131072)
    A continuation hint reports the next start/start_module when more data exists.

## Adapter-Specific Notes

### AdapterID / "type" field
  Some adapters (vsdbg) require a specific adapterID in the DAP initialize handshake.
  If launch_args contains "type", that value is used as adapterID.
  Otherwise, the adapter binary filename (without extension) is used.
  If initialize fails, try adding "type" to launch_args with the adapter's expected ID.

### Client ID / Client Name
  Some adapters check clientID for licensing (vsdbg requires "vscode").
  Use the dedicated client_id and client_name parameters for common overrides.
  For advanced cases, __ (double underscore) prefixed keys in launch_args are
  meta fields consumed by this tool and stripped before sending to the adapter.
  Example: "__clientID":"vscode" in launch_args has the same effect as client_id="vscode".
  Priority: dedicated parameter > __ meta field > default ("agent-tool").

### Registers
  Registers are exposed through scopes -> variables, NOT a separate operation.
  The adapter must include a "Registers" scope in the scopes response.
  - dlv: set "showRegisters":true in launch_args
  - codelldb/lldb-dap: registers shown by default
  - debugpy: not applicable (Python has no CPU registers)

### Features vary by adapter
  operation=status after launch lists what the adapter supports. An unsupported
  operation returns an error, which is normal: dlv has disassemble but not
  modules, debugpy the reverse. A missing feature (registers, conditional
  breakpoints) is usually a launch_args setting of that adapter, not a tool limit.

### Release builds
  Optimized builds show <optimized out> or wrong values, skip lines, drop stack
  frames, and set_variable can report success without effect. Rebuild
  unoptimized when variable inspection matters.

### Breakpoint Timing
  Set breakpoints AFTER launch but BEFORE the first continue.
  The tool sends configurationDone automatically on the first continue.

## Using Other Adapters
  Any DAP adapter works. For an unlisted one, check its docs for:
     - stdio vs TCP mode
     - required launch_args fields (program, cwd, request, ...)
     - the "type" value it expects (e.g. "cppvsdbg" for vsdbg)
  initialize failing with a vague error is usually a wrong adapterID: set "type"
  in launch_args. If launch succeeds but nothing runs, operation=status shows
  the error events (e.g. a license restriction).

## Tips
- If timeout occurs, use operation=status to check state and poll events
- Variables use reference IDs -- get them from scopes response
- References are only valid while stopped; they reset on continue
- Max 5 concurrent debug sessions (oldest evicted at capacity)
- Sessions auto-expire after 30 minutes of inactivity
- Always disconnect when done to clean up adapter processes

## Debugging Tips for Specific Scenarios

### Node.js under codelldb (LLDB)
  When debugging Node.js scripts under codelldb, async operations (setTimeout,
  setImmediate, Promise callbacks) may NOT execute -- Node's event loop doesn't
  tick properly under LLDB's stdio capture.
  Workaround: Use synchronous scripts only. Replace async patterns with sync
  equivalents (e.g., require() instead of dynamic import, synchronous loops
  instead of setTimeout).

### LLDB commands via evaluate
  codelldb supports LLDB native commands through evaluate with context="repl".
  Example: evaluate(expression="breakpoint set -a 0x7470", context="repl")
  These may return empty "Result: " strings but still execute successfully.
  Use "breakpoint list" to verify breakpoints were set.
  This is useful for instruction-level breakpoints when set_instruction_breakpoints
  fails (some adapters have parsing issues with hex addresses).

### Reading native code / DLL internals
  Use codelldb with read_memory and disassemble for low-level inspection.
  For native addon analysis (e.g., .node files), load them in a host process
  (Node.js for .node files) and set instruction breakpoints at known RVAs.
  Runtime address = the module's loaded base (operation=modules, or
  resolve_address on any address inside it) + RVA. ASLR moves DLLs, so the
  preferred base in the PE header (often 0x180000000) is usually not it.`
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
- Indentation differs (tabs vs spaces) -- agent-tool handles this automatically
- Line endings differ (CRLF vs LF) -- agent-tool matches either, including files
  that mix both
- Invisible characters or encoding differences
- The text was already changed

## File encoding changed after edit
This shouldn't happen -- agent-tool preserves the original encoding.
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

func helpMemtool() string {
	return `# Memory Tool (memtool)

Process memory tool for reverse engineering and game hacking.
CheatEngine-style: search, filter, write, read_chain, pointer scan, struct search, diff.

## Long scans
A call still running after ~15s (large search/snapshot/filter/pointer_scan/diff) returns a job_id;
collect it with toolbox operation=job job_action=wait. job_action=cancel stops the scan within one
chunk; a cancelled filter is rolled back, so the session keeps its previous matches. While a session
is busy, other calls on it fail fast instead of queueing.

## Platform Support
Windows and Linux. macOS is not supported.

## Operations

### regions - List memory regions
  memtool(operation="regions", pid=1234)
  memtool(operation="regions", pid=1234, protection="rw")

### search - Initial value scan (creates session)
  memtool(operation="search", pid=1234, value_type="int32", value="100")
  memtool(operation="search", pid=1234, value_type="bytes", value="4D 5A 90 00")
  memtool(operation="search", pid=1234, value_type="int32")  # unknown initial value
  Omit 'value' for unknown initial value scan -- takes a full snapshot and
  lets you filter by changed/unchanged/increased/decreased.

### filter - Narrow matches (requires session_id)
  memtool(operation="filter", session_id="abc", filter_type="decreased")
  memtool(operation="filter", session_id="abc", filter_type="exact", value="95")
  Types: exact, changed, unchanged, increased, decreased

### undo - Restore previous filter state
  memtool(operation="undo", session_id="abc")

### read - Hex dump at address
  memtool(operation="read", pid=1234, address="0x7FF6A1B20000", length=128)

### read_chain - Resolve base+offset pointer chains (batched)
  Cheat-Engine semantics: p=deref(base); deref each middle offset; last offset
  is added (not dereferenced); then the value is read at the final address.
  Batch many chains in one call so you don't need one read per pointer level.
  memtool(operation="read_chain", pid=1234, chains='[
    {"base":"0x7FF6..","offsets":["0x10","0x8","0x0"],"type":"int32","label":"hp"},
    {"base":"0x7FF6..","offsets":["0x20"],"type":"float32","label":"x"}]')
  Single chain (flat form): address + offsets + value_type
  memtool(operation="read_chain", pid=1234, address="0x7FF6..",
	offsets="0x10, 0x8, 0x0", value_type="int32")
  Offsets are signed (e.g. "-0x8"). Empty offsets reads directly at base.
  type omitted -> hex dump (length bytes). ptr_size=4 for a 32-bit target.
  Broken chains report the exact step that failed (e.g. "BROKEN at step 2").

### write - Modify memory at address
  memtool(operation="write", pid=1234, address="0x...", value_type="int32", value="999")
  memtool(operation="write", pid=1234, address="0x...", value_type="bytes", value="90 90 90 90")

### disasm - Disassemble live process memory
  memtool(operation="disasm", pid=1234, address="0x7FF6A1B20000")
  memtool(operation="disasm", pid=1234, address="0x...", count=100, arch="x86", mode=64)
  memtool(operation="disasm", pid=1234, address="0x...", arch="arm", mode=64)
  x86/x64/ARM/ARM64. Lines are address + instruction; show_bytes=true adds the hex encoding column.

### struct_search - Multi-field pattern search
  memtool(operation="struct_search", pid=1234,
	struct_pattern='[{"offset":0,"type":"int32","value":"100"},{"offset":4,"type":"int32","value":"50"}]')

### pointer_scan - Find pointer chains to an address
  memtool(operation="pointer_scan", pid=1234, address="0x...", max_depth=3, max_offset=4096)

### diff - Compare memory snapshots
  memtool(operation="diff", pid=1234)             # take first snapshot
  memtool(operation="diff", session_id="abc")      # compare with current

### force_dacl - Bypass a same-user process's hardened DACL (Windows, opt-in)
  memtool(operation="read", pid=1234, address="0x...", force_dacl=true)
  When a normal open is denied, temporarily rewrites the target's DACL, opens
  the handle, then restores the original DACL. Only for same-user targets that
  hardened their own DACL -- cannot bypass higher-integrity, other-user, or
  PPL/anti-cheat processes.

### info / close - Session management
  memtool(operation="info", session_id="abc")
  memtool(operation="close", session_id="abc")

## CheatEngine Workflow

### Known value:
  1. search(pid, value_type="int32", value="100") -> session, N matches
  2. [value changes] -> filter(session, filter_type="decreased")
  3. [value changes] -> filter(session, filter_type="exact", value="95")
  4. info(session) -> addresses + current values
  5. write(pid, address, value_type="int32", value="999") -> modify
  6. close(session)

### Unknown initial value:
  1. search(pid, value_type="int32") -> session (snapshot taken)
  2. [value changes] -> filter(session, filter_type="changed") -> N matches
  3. [value stable]  -> filter(session, filter_type="unchanged")
  4. [value changes] -> filter(session, filter_type="decreased")
  5. info(session) -> narrowed addresses
  6. write + close

## Session/Performance
  - Max 3 sessions (oldest evicted), 10min idle timeout
  - Up to 100M matches per session; snapshots and diff handle multi-GB processes
  - Undo stack: up to 5 levels

## Permissions
  - Windows: same-user processes work without elevation. memtool auto-enables
    SeDebugPrivilege, so running elevated (Administrator) additionally allows
    reading DACL-hardened or higher-integrity processes. PPL/anti-cheat
    (kernel-protected) processes cannot be read from user mode at any privilege.
  - Linux: same-user or root, or CAP_SYS_PTRACE`
}

func helpWintool() string {
	return `# wintool -- Windows GUI Automation

Windows-only tool for finding, inspecting, and controlling windows.
macOS and Linux are not supported.

## Operations

### Discovery
  - list: Enumerate all top-level windows (HWND, PID, title, class, rect, visible)
    Supports filters: title, class, pid
  - find: Search windows by title/class/PID (at least one required)
  - tree: Show child window/control hierarchy of a specific window
  - inspect: Detailed info (styles, rect, client area, children count)

### Observation
  - screenshot: Capture a window as base64 PNG (works even if occluded)
    Max resolution: 4096x4096. Default: returns ImageContent (base64).
    Use save_path="temp" for temp file, or save_path="/path/to/file.png".
  - clipboard: Read image from system clipboard as PNG
    Use after Win+Shift+S or image copy.
    Default: returns ImageContent (base64). Use save_path for file output.
  - gettext: Read text from a window/control via WM_GETTEXT

### Interaction
  - settext: Set text on a window/control via WM_SETTEXT
  - click: Click at client-relative coordinates (left/right/middle)
  - type: Send keyboard characters to a GUI window or a console (cmd/PowerShell)
    Tip: type + send(msg=0x0100, wparam=0x0D) injects commands into terminals/IDEs
  - send: Raw SendMessage/PostMessage with custom msg/wParam/lParam
  - close: Send WM_CLOSE to a window
  - focus: Bring window to foreground (SetForegroundWindow)
  - show: Change window state (show/hide/minimize/maximize/restore)
  - move: Move and/or resize a window

## Workflow Examples

### Read clipboard image (e.g. after Win+Shift+S):
  1. clipboard -> returns ImageContent (agent can "see" it directly)
  2. Or: clipboard(save_path="temp") -> saves to temp file, read it later

### Find and screenshot a window:
  1. list (or find title="Notepad") -> get HWND (e.g. 0x1A2B3C)
  2. screenshot(hwnd="0x1A2B3C") -> returns ImageContent (agent can "see" it)
  3. tree(hwnd="0x1A2B3C") -> find Edit control HWND
  4. gettext(hwnd=edit_hwnd) -> read current text

### Automate a GUI application:
  1. find(title="MyApp") -> HWND
  2. tree -> find button/edit controls
  3. settext(hwnd=edit_ctrl, text="input value")
  4. click(hwnd=button_ctrl, x=10, y=10) -> click the button
  5. screenshot -> verify result

### Low-level message control:
  send(hwnd, msg=0x0111, wparam=button_id) -> WM_COMMAND
  send(hwnd, msg=0x0010) -> WM_CLOSE

## Notes
  - HWND is specified as hex string: "0x1A2B3C" or "1A2B3C"
  - Coordinates for click are client-relative (not screen coordinates)
  - SetForegroundWindow may fail if agent-tool is not the foreground process
  - screenshot/clipboard return ImageContent by default (base64 PNG)
    Use save_path to save to file instead (save_path="temp" or absolute path)`
}

func helpCodegraph() string {
	return `# codegraph - AST-based Code Indexing

Indexes symbols, calls and inheritance of a project for precise lookup without
grep noise. No compiler or language server is needed.

## Operations

  codegraph(operation="index", path="/project/root")
    Build or update the code index. Incremental: only re-parses changed files.
    Creates .codegraph.db at the project root (add to .gitignore).

  codegraph(operation="find", name="Monster", path="/project/root")
    Find symbol definitions by name. Searches name and qualified_name.

  codegraph(operation="callers", name="takeDamage", path="/project/root")
    Find all call sites that invoke a function/method.

  codegraph(operation="callees", name="main", path="/project/root")
    Find all functions called by a function (within its body).

  codegraph(operation="symbols", path="/path/to/file.cpp")
    List all symbols in a file (classes, functions, calls). No index needed.
    symbols and callees support offset + max_results (default 500, max 100000)
    and max_output_chars (default 32768, max 131072). Follow the returned
    next-offset hint to continue.

  codegraph(operation="methods", name="Monster", path="/project/root")
    List all methods of a class.

  codegraph(operation="inherits", name="Dog", path="/project/root")
    Show inheritance hierarchy (parents and children).

  codegraph(operation="stats", path="/project/root")
    Project statistics: file/class/function/method/call counts by language.

  codegraph(operation="importers", name="dap_server.h", path="/project/root")
    Find all files that import/include a given file.

  codegraph(operation="unused", path="/project/root")
    Find functions/methods defined but never called (dead code detection).

  codegraph(operation="call_tree", name="HandleRequest", path="/project/root", depth=3, direction="up")
    Recursive call hierarchy. direction: up (callers) or down (callees). Default depth 3.

## Workflow

  1. codegraph(operation="index", path="/project/root")   -- build index (once)
  2. codegraph(operation="stats")                          -- project overview
  3. codegraph(operation="find", name="Player")            -- find definitions
  4. codegraph(operation="methods", name="Player")          -- list methods
  5. codegraph(operation="callers", name="takeDamage")      -- who calls this?
  6. codegraph(operation="call_tree", name="takeDamage", direction="up")  -- full call chain
  7. codegraph(operation="unused")                          -- dead code
  8. After editing, re-run index to update changed files

## Supported Languages

  C/C++ (.cpp, .cc, .cxx, .c, .h, .hpp, .hxx, .hh)
  Python (.py), Go (.go), C# (.cs), Rust (.rs), Java (.java)

## Filtering

  Automatically skips: .git, node_modules, __pycache__, build, bin, obj,
  venv, .venv, vendor, third_party, dist, target, and other non-source dirs.
  Respects .gitignore if present at the project root.

## Key Points

  - symbols parses one file directly; the other lookups read the index, so run index first
  - Index is local per-project (.codegraph.db); updates re-parse only changed files
  - call_tree replaces chaining callers/callees calls by hand`
}
