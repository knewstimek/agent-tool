# agent-tool

[한국어](README.ko.md)

MCP (Model Context Protocol) tool server for AI coding agents.

## Why?

Built-in Edit tools in AI coding agents (Claude Code, Cursor, Codex, etc.) have known limitations:

- **Tab indentation breaks**: LLMs output spaces, but your project uses tabs. The built-in Edit tool writes spaces as-is, corrupting your indentation style.
- **Encoding corruption**: Editing EUC-KR, Shift-JIS, or UTF-8 BOM files silently converts them to plain UTF-8, breaking legacy projects.
- **No SSH/SFTP**: Can't manage remote servers or transfer files directly from the agent.

**agent-tool** solves these by providing drop-in replacement tools that respect your project's conventions.

## Supported Agents

Claude Code, Codex CLI, Cursor, Windsurf, Cline, Gemini CLI, and any MCP-compatible agent.

## Features

| Tool | Description | Status |
|------|-------------|--------|
| **Edit** | String replacement with smart indentation and encoding preservation (supports dry_run) | ✅ |
| **Read** | Encoding-aware file reading with line range support | ✅ |
| **Write** | Encoding-aware file creation/overwrite | ✅ |
| **Grep** | Encoding-aware regex content search | ✅ |
| **Glob** | File pattern matching with `**` recursive support | ✅ |
| **ListDir** | Tree-style directory listing | ✅ |
| **Diff** | Compare two files with unified diff output (encoding-aware) | ✅ |
| **Patch** | Apply unified diff patch to a file (supports dry_run) | ✅ |
| **Checksum** | Compute file hash (md5, sha1, sha256) | ✅ |
| **FileInfo** | File metadata (size, encoding, line ending, indentation, line count) | ✅ |
| **Compress** | Create zip / tar.gz archives | ✅ |
| **Decompress** | Extract zip / tar.gz archives (Zip Slip/Bomb protection) | ✅ |
| **Backup** | Timestamped zip backup with exclude patterns. dry_run preview with directory stats, pattern match counts, and largest files | ✅ |
| **ConvertEncoding** | Convert file encoding (EUC-KR ↔ UTF-8, add/remove BOM, etc.) | ✅ |
| **Delete** | Safe single-file deletion (no directories, no symlinks, system path protection, dry_run) | ✅ |
| **Rename** | Atomic file/directory rename or move (dry_run) | ✅ |
| **SysInfo** | System information — OS, CPU, RAM, disk, uptime, CPU usage measurement | ✅ |
| **FindTools** | Discover installed dev tools — compilers, runtimes, build systems (Go, .NET, Node, Python, Java, Rust, C/C++, etc.). Searches PATH, env vars, and known locations (~/bin, snap, scoop, Homebrew, SDKMAN, nvm, fnm, pyenv) | ✅ |
| **ProcList** | List running processes — PID, name, command line, memory. Sensitive args auto-masked. Filter by name or port | ✅ |
| **ProcKill** | Kill, suspend, or resume processes by PID or port. Tree kill, signal selection (kill/term/hup/int/stop/cont), zombie handling (Linux), dry_run | ✅ |
| **ProcExec** | Execute commands as new processes. Foreground/background/suspended start (Windows: CREATE_SUSPENDED, Linux: SIGSTOP). Timeout, env vars | ✅ |
| **EnvVar** | Read environment variables. Sensitive values (passwords, tokens) auto-masked | ✅ |
| **Firewall** | Read firewall rules — iptables/nftables/firewalld (Linux), netsh (Windows). Read-only | ✅ |
| **SSH** | Execute commands on remote servers via SSH. Password & key auth, session pooling, host key verification (strict/tofu/none), ProxyJump (IPv4→IPv6 bastion), IPv6 support | ✅ |
| **SFTP** | Transfer files and manage remote filesystems over SSH. Upload, download, ls, stat, mkdir, rm, chmod, rename. Reuses SSH session pool. Max 2 GB per transfer | ✅ |
| **SetConfig** | Change runtime settings (encoding, file size limit, symlinks, workspace, etc.) | ✅ |
| **Help** | Built-in usage guide for agents (encoding, indentation, troubleshooting) | ✅ |

## Key Improvements

### Smart Indentation
LLMs typically output spaces, but many projects use tabs. AgentTool auto-converts indentation to match the file's existing style.

- Reads `.editorconfig` for `indent_style` and `indent_size`
- Falls back to content-based detection (first 100 lines)
- Protects legacy files: won't convert if actual content contradicts `.editorconfig`

### Encoding Preservation
Edits preserve the original file encoding instead of forcing UTF-8.

- **Detection priority**: `.editorconfig` charset → chardet auto-detection → fallback encoding
- **Supported**: UTF-8, UTF-8 BOM, EUC-KR, Shift-JIS, ISO-8859-1, UTF-16, and more
- **Line endings**: Preserves `\r\n` / `\n` as-is

## Quick Start

1. Download the binary for your OS from [Releases](https://github.com/knewstimek/agent-tool/releases/latest)
2. Run `agent-tool install` (or `agent-tool install claude` for a specific agent)
3. Restart your IDE / agent
4. Done — all tools are available immediately with no permission popups

Or just ask your AI agent to do it for you:
> "Download agent-tool from https://github.com/knewstimek/agent-tool/releases/latest and run `agent-tool install`"

Any capable AI coding agent (Claude Code, Codex, etc.) can handle the full download → install → restart flow automatically.

## Installation

### Auto-install (recommended)

```bash
# Register with all detected agents
agent-tool install

# Register with a specific agent
agent-tool install claude
agent-tool install codex
agent-tool install cursor
agent-tool install windsurf

# Uninstall (removes agent-tool entry only, preserves other settings)
agent-tool uninstall          # from all agents
agent-tool uninstall claude   # from specific agent
```

### Manual setup

**Claude Code / Cursor / Cline** (`settings.json` or `mcp.json`):
```json
{
  "mcpServers": {
    "agent-tool": {
      "command": "/path/to/agent-tool"
    }
  }
}
```

**Codex CLI** (`~/.codex/config.toml`):
```toml
[mcp_servers.agent-tool]
command = "/path/to/agent-tool"
```

### Options

```bash
# Set fallback encoding for projects with non-UTF-8 files
agent-tool --fallback-encoding EUC-KR
```

### Environment Variable

Set `AGENT_TOOL_FALLBACK_ENCODING` to avoid repeating the CLI flag every session:

```bash
# Windows (no admin required)
setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR

# Linux / macOS (add to ~/.bashrc or ~/.zshrc)
export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR
```

Priority: CLI flag > environment variable > default (UTF-8).

### Runtime Configuration

Agents can change settings at runtime via `set_config` without restarting:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `fallback_encoding` | Fallback encoding when auto-detection fails | `UTF-8` |
| `encoding_warnings` | Show encoding detection warnings | `true` |
| `max_file_size_mb` | Max file size for read/edit/grep (MB) | `50` |
| `allow_symlinks` | Allow symlink extraction from tar archives | `false` |
| `workspace` | Default workspace/project root for tools like glob when no explicit path is given | _(cwd)_ |

## Build

```bash
go build -o agent-tool .
```

Cross-compile:
```bash
GOOS=linux GOARCH=amd64 go build -o agent-tool .
GOOS=darwin GOARCH=arm64 go build -o agent-tool .
GOOS=windows GOARCH=amd64 go build -o agent-tool.exe .
```

## Troubleshooting

### Garbled text (encoding issues)

If Korean, Japanese, or other non-ASCII text appears as garbage characters:

**Option 1**: Add `charset` to your `.editorconfig`:
```ini
[*]
charset = euc-kr
```

**Option 2**: Set environment variable (persistent):
```bash
setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR   # Windows
export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR  # Linux
```

**Option 3**: CLI flag (per-session):
```bash
agent-tool --fallback-encoding EUC-KR
```

### Built-in help for agents

agent-tool includes a `agent_tool_help` tool that agents can call for usage guidance. When an agent encounters encoding warnings or garbled text, it can call:

```json
{ "tool": "agent_tool_help", "arguments": { "topic": "encoding" } }
```

Available topics: `overview`, `encoding`, `indentation`, `tools`, `troubleshooting`

## Security

- **Zip Slip protection**: Archive entries with `../` path traversal are blocked (both zip and tar)
- **Zip Bomb protection**: Single file limit (1GB), total extraction limit (5GB)
- **Symlinks**: Skipped by default. Enable via `set_config allow_symlinks=true` (tar only; zip symlinks always skipped). Even when enabled, symlinks targeting outside the output directory are blocked
- **File size limit**: Configurable max file size (default 50MB) prevents OOM on large files. Adjustable via `set_config max_file_size_mb=N`
- **Encoding safety**: chardet uses 64KB sample (not full file) for memory efficiency

## Tech Stack

- **Language**: Go
- **MCP SDK**: [github.com/modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
- **Encoding**: saintfish/chardet + golang.org/x/text
- **Distribution**: Single binary (cross-compiled)

## License

[MIT](LICENSE)
