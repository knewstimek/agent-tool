# AgentTool

[English](README.md)

AI 코딩 에이전트를 위한 MCP(Model Context Protocol) 도구 서버.

내장 도구의 한계(인코딩, 탭 처리)를 개선하고, 새로운 기능(SSH, 압축, 백업)을 추가합니다.

## 지원 에이전트

Claude Code, Codex CLI, Cursor, Windsurf, Cline, Gemini CLI 및 모든 MCP 호환 에이전트.

## 기능

| 도구 | 설명 | 상태 |
|------|------|------|
| **Edit** | 스마트 들여쓰기 + 인코딩 보존 문자열 치환 | ✅ |
| **Read** | 인코딩 인식 파일 읽기 (줄 범위 지정) | ✅ |
| **Grep** | 인코딩 인식 정규식 내용 검색 | ✅ |
| **Glob** | `**` 재귀 지원 파일 패턴 매칭 | ✅ |
| Write | 인코딩 인식 파일 생성/덮어쓰기 | 예정 |
| ListDir | 트리 구조 디렉토리 목록 | 예정 |
| Compress / Decompress | Zip 압축/해제 | 예정 |
| Backup | 타임스탬프 zip 백업 | 예정 |
| SSH | 원격 서버 접속 및 명령 실행 | 예정 |
| SFTP | SSH 경유 파일 업로드/다운로드 | 예정 |

## 핵심 개선사항

### 스마트 들여쓰기
LLM은 보통 공백으로 출력하지만, 많은 프로젝트가 탭을 사용합니다. AgentTool은 파일의 기존 스타일에 맞게 들여쓰기를 자동 변환합니다.

- `.editorconfig`에서 `indent_style`, `indent_size` 읽기
- 설정이 없으면 파일 내용 기반 감지 (앞 100줄 스캔)
- 레거시 파일 보호: 실제 내용이 `.editorconfig`와 다르면 변환하지 않음

### 인코딩 보존
UTF-8로 강제 변환하지 않고, 원본 파일 인코딩을 유지합니다.

- **감지 우선순위**: `.editorconfig` charset → chardet 자동 감지 → 폴백 인코딩
- **지원 인코딩**: UTF-8, UTF-8 BOM, EUC-KR, Shift-JIS, ISO-8859-1, UTF-16 등
- **줄바꿈**: `\r\n` / `\n` 원본 유지

## 설치

### 자동 설치 (권장)

```bash
# 감지된 모든 에이전트에 자동 등록
agent-tool install

# 특정 에이전트에만 등록
agent-tool install claude
agent-tool install codex
agent-tool install cursor
agent-tool install windsurf
```

### 수동 설정

**Claude Code / Cursor / Cline** (`settings.json` 또는 `mcp.json`):
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

### 옵션

```bash
# UTF-8이 아닌 프로젝트에서 폴백 인코딩 지정
agent-tool --fallback-encoding EUC-KR
```

## 빌드

```bash
go build -o agent-tool .
```

크로스 컴파일:
```bash
GOOS=linux GOARCH=amd64 go build -o agent-tool .
GOOS=darwin GOARCH=arm64 go build -o agent-tool .
GOOS=windows GOARCH=amd64 go build -o agent-tool.exe .
```

## 기술 스택

- **언어**: Go
- **MCP SDK**: [github.com/modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
- **인코딩**: saintfish/chardet + golang.org/x/text
- **배포**: 단일 바이너리 (크로스 컴파일)

## 라이선스

[MIT](LICENSE)
