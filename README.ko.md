# agent-tool

[English](README.md)

AI 코딩 에이전트를 위한 MCP(Model Context Protocol) 도구 서버.

## 왜 만들었나?

AI 코딩 에이전트(Claude Code, Cursor, Codex 등)의 내장 Edit 도구에는 알려진 한계가 있습니다:

- **탭 들여쓰기 깨짐**: LLM은 공백을 출력하지만, 프로젝트는 탭을 사용. 내장 Edit는 공백을 그대로 써서 들여쓰기 스타일이 망가짐.
- **인코딩 손상**: EUC-KR, Shift-JIS, UTF-8 BOM 파일을 편집하면 조용히 UTF-8로 변환되어 레거시 프로젝트가 깨짐.
- **SSH/SFTP 미지원**: 에이전트에서 원격 서버를 직접 관리할 수 없음.

**agent-tool**은 프로젝트의 규칙을 존중하는 대체 도구를 제공합니다.

## 지원 에이전트

Claude Code, Codex CLI, Cursor, Windsurf, Cline, Gemini CLI 및 모든 MCP 호환 에이전트.

## 기능

| 도구 | 설명 | 상태 |
|------|------|------|
| **Edit** | 스마트 들여쓰기 + 인코딩 보존 문자열 치환 | ✅ |
| **Read** | 인코딩 인식 파일 읽기 (줄 범위 지정) | ✅ |
| **Write** | 인코딩 인식 파일 생성/덮어쓰기 | ✅ |
| **Grep** | 인코딩 인식 정규식 내용 검색 | ✅ |
| **Glob** | `**` 재귀 지원 파일 패턴 매칭 | ✅ |
| **ListDir** | 트리 구조 디렉토리 목록 | ✅ |
| **Compress** | zip / tar.gz 압축 | ✅ |
| **Decompress** | zip / tar.gz 해제 (Zip Slip/Bomb 보호) | ✅ |
| **Backup** | 타임스탬프 zip 백업 (제외 패턴 지원) | ✅ |
| **ConvertEncoding** | 파일 인코딩 변환 (EUC-KR ↔ UTF-8, BOM 추가/제거 등) | ✅ |
| **SetConfig** | 런타임 설정 변경 (인코딩, 파일 크기 제한, symlink 등) | ✅ |
| **Help** | 에이전트용 사용법 안내 (인코딩, 들여쓰기, 트러블슈팅) | ✅ |
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

# 제거 (agent-tool 항목만 삭제, 다른 설정은 보존)
agent-tool uninstall          # 모든 에이전트에서 제거
agent-tool uninstall claude   # 특정 에이전트에서만 제거
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

### 환경변수

세션마다 CLI 플래그를 반복하지 않으려면 환경변수를 설정하세요:

```bash
# Windows (관리자 권한 불필요)
setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR

# Linux / macOS (~/.bashrc 또는 ~/.zshrc에 추가)
export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR
```

우선순위: CLI 플래그 > 환경변수 > 기본값 (UTF-8).

### 런타임 설정

에이전트가 `set_config` 도구로 재시작 없이 설정을 변경할 수 있습니다:

| 파라미터 | 설명 | 기본값 |
|----------|------|--------|
| `fallback_encoding` | 자동 감지 실패 시 폴백 인코딩 | `UTF-8` |
| `encoding_warnings` | 인코딩 감지 경고 표시 | `true` |
| `max_file_size_mb` | read/edit/grep 최대 파일 크기 (MB) | `50` |
| `allow_symlinks` | tar 압축 해제 시 symlink 생성 허용 | `false` |

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

## 트러블슈팅

### 한글/일본어가 깨져 보일 때 (인코딩 문제)

**방법 1**: `.editorconfig`에 `charset` 추가:
```ini
[*]
charset = euc-kr
```

**방법 2**: 환경변수로 영구 설정:
```bash
setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR   # Windows
export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR  # Linux
```

**방법 3**: CLI 플래그 (세션별):
```bash
agent-tool --fallback-encoding EUC-KR
```

### 에이전트용 내장 도움말

agent-tool은 `agent_tool_help` 도구를 제공합니다. 에이전트가 인코딩 경고나 깨진 텍스트를 만나면 자동으로 사용법을 확인할 수 있습니다.

사용 가능 토픽: `overview`, `encoding`, `indentation`, `tools`, `troubleshooting`

## 보안

- **Zip Slip 보호**: `../` 경로 조작을 통한 Path Traversal 차단 (zip, tar 모두)
- **Zip Bomb 보호**: 단일 파일 1GB, 총 추출 크기 5GB 제한
- **Symlink**: 기본 스킵 (보안). `set_config allow_symlinks=true`로 활성화 (tar만 지원). 활성화해도 outputDir 밖을 가리키는 symlink는 차단
- **파일 크기 제한**: 설정 가능한 최대 파일 크기 (기본 50MB)로 OOM 방지
- **인코딩 안전성**: chardet는 64KB 샘플만 사용하여 메모리 효율적

## 기술 스택

- **언어**: Go
- **MCP SDK**: [github.com/modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
- **인코딩**: saintfish/chardet + golang.org/x/text
- **배포**: 단일 바이너리 (크로스 컴파일)

## 라이선스

[MIT](LICENSE)
