# AgentTool

[한국어](README.ko.md)

MCP (Model Context Protocol) tool server for AI coding agents.

Improves built-in tool limitations (encoding, tab handling) and adds new capabilities (SSH, compression, backup).

## Supported Agents

Claude Code, Codex CLI, Cursor, Windsurf, Cline, Gemini CLI, and any MCP-compatible agent.

## Features

| Tool | Description | Status |
|------|-------------|--------|
| **Edit** | String replacement with smart indentation and encoding preservation | ✅ |
| **Read** | Encoding-aware file reading with line range support | ✅ |
| **Grep** | Encoding-aware regex content search | ✅ |
| **Glob** | File pattern matching with `**` recursive support | ✅ |
| Write | Encoding-aware file creation/overwrite | Planned |
| ListDir | Tree-style directory listing | Planned |
| Compress / Decompress | Zip compression | Planned |
| Backup | Timestamped zip backup | Planned |
| SSH | Remote server connection and command execution | Planned |
| SFTP | File upload/download over SSH | Planned |

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

## Tech Stack

- **Language**: Go
- **MCP SDK**: [github.com/modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
- **Encoding**: saintfish/chardet + golang.org/x/text
- **Distribution**: Single binary (cross-compiled)

## License

[MIT](LICENSE)
