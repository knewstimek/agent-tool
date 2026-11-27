# agent-tool

[English](README.md)

<a href="https://glama.ai/mcp/servers/knewstimek/agent-tool">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/knewstimek/agent-tool/badge" alt="agent-tool MCP server" />
</a>

AI 코딩 에이전트를 위한 MCP(Model Context Protocol) 도구 서버.

## 왜 만들었나?

AI 코딩 에이전트(Claude Code, Cursor, Codex 등)의 내장 도구에는 알려진 한계가 있습니다:

- **탭 들여쓰기 깨짐**: LLM은 공백을 출력하지만, 프로젝트는 탭을 사용. 내장 Edit는 공백을 그대로 써서 들여쓰기 스타일이 망가짐.
- **인코딩 손상**: EUC-KR, Shift-JIS, GB18030 파일을 편집하면 조용히 UTF-8로 변환되어 레거시 프로젝트가 깨짐.
- **도구가 너무 분산됨**: Redis CLI, MySQL/SSH 클라이언트를 따로 찾고 설정하는 과정은 번거롭고 오류가 잦음. agent-tool은 40개 도구를 한 바이너리로 통합하고 compact 프로필과 고정 toolbox gateway로 필요할 때 호출함.
- **리버스 엔지니어링 지원 부재**: 내장 도구로는 바이너리 디스어셈블, PE/ELF 헤더 분석, 함수 경계 탐지, 크로스 레퍼런스 검색이 불가능. agent-tool은 정적 바이너리 분석(디스어셈블리, PDB/DWARF 타입을 적용한 C 디컴파일, xref, 함수 탐지), DAP 디버거, CheatEngine 스타일 메모리 도구를 포함 -- 에이전트에게 완전한 리버스 엔지니어링 능력을 부여.
- **네트워크 검열**: 일부 국가에서 정부 수준의 웹 필터링으로 `curl`/`wget` 요청이 차단됨. agent-tool은 ECH (Encrypted Client Hello)와 DoH (DNS over HTTPS)를 기본 활성화하여 이런 제한을 우회.

**agent-tool**은 프로젝트 규칙을 보존하면서 모델 컨텍스트를 제한하는 에이전트 지향 도구를 제공합니다.

## 지원 에이전트

Claude Code, Codex CLI, Cursor, Windsurf, Cline, Gemini CLI 및 모든 MCP 호환 에이전트.

## LLM 친화적 기본 동작

기본 `core` 프로필은 40개 전체 스키마 대신 `toolbox`를 포함한 11개만 노출합니다.
실제 MCP 프로토콜 측정에서 직렬화된 도구 목록은 `full` 약 74KB에서 약 15KB로
줄었습니다. 상시 컨텍스트를 최소화하려면 `--profile core-lite`로 약 6.4KB인
`read`, `write`, `edit`, `grep`, `toolbox`만 노출할 수 있습니다. `toolbox(operation="describe", tool="ssh", compact=true,
tool_operation="execute")`로 한 operation에 필요한 필드와 required 목록만 확인한 뒤
`toolbox(operation="call", tool="ssh", arguments={...})`로
호출할 수 있습니다. 이 gateway는 동적 도구 목록 갱신에 의존하지 않아 Codex 같은
고정 binding 클라이언트에서도 동작합니다. describe가 반환한 tool/version 기반
`schema_handle`을 다음 describe에 전달하면 스키마가 그대로일 때 짧은 확인만 반환합니다.
SSH 실행, MySQL 쿼리, 파일 복사, Windows 스크린샷/클립보드 이미지, 정적 분석의
주요 operation은 compact 스키마를 지원합니다. 또는
`--profile core-lite|coding|remote|analysis|full`로 시작할 수 있습니다.

대용량 텍스트 결과는 기본 32K자, 절대 상한 128K이며 잘림을 숨기지 않습니다.
페이지 가능 도구는 `next_offset` 또는 `next_cursor`를 반환합니다. 로컬 상대경로는
명시적 workspace, MCP 클라이언트 root, 서버 cwd 순서로 해석됩니다.

## 기능

| 도구 | 설명 | 상태 |
|------|------|------|
| **Edit** | 스마트 들여쓰기 + 인코딩 보존 문자열 치환 (dry_run 지원) | ✅ |
| **Read** | 인코딩 인식 줄번호 읽기. 기본 400줄/32K자, 명시적 truncation과 정확한 `next_offset`, 초장문 행 안전 처리, 선택적 SHA-256, 이미지 ImageContent | ✅ |
| **Write** | 인코딩 인식 파일 생성/덮어쓰기 | ✅ |
| **Grep** | 기본 32K 예산, 파일별 compact 묶음 출력, 상대경로, `.gitignore`/`.ignore`/생성 디렉터리 제외, 바이너리 감지, 중복 없는 결정적 `next_cursor` 페이징 | ✅ |
| **Glob** | 정렬·제한된 `**` 검색. 상대경로, `.gitignore`/`.ignore`/생성 디렉터리 제외, 명시적 `has_more`, 결정적 cursor 페이징 | ✅ |
| **ListDir** | 출력 제한·페이징 디렉토리 목록. max_entries + continuation cursor, 디렉토리/파일 필터, 이름 glob 필터, counts-only, flat/tree 지원 | ✅ |
| **Diff** | 두 파일 비교 (unified diff 출력, 인코딩 인식). 줄바꿈이나 끝 개행만 다른 경우 빈 diff 대신 그 사실을 명시 | ✅ |
| **Patch** | unified diff 패치 적용 (dry_run 지원). 줄마다 자기 줄바꿈을 유지하므로 CRLF/LF 혼합 파일이 재작성되지 않음 | ✅ |
| **Checksum** | 파일 해시 계산 (md5, sha1, sha256) | ✅ |
| **FileInfo** | 파일 메타데이터 (크기, 인코딩, 혼합 줄바꿈별 개수, 들여쓰기, 줄 수) | ✅ |
| **ConvertEncoding** | 파일 인코딩 변환 (EUC-KR ↔ UTF-8, BOM 추가/제거 등) | ✅ |
| **Delete** | 안전한 파일/디렉토리 삭제와 최대 100개 `file_paths` 일괄 처리. 디렉토리는 `recursive=true` 필요, 보호 경로·심볼릭링크 차단, 오류 제한, dry_run 미리보기 | ✅ |
| **Rename** | 원자적 파일/디렉토리 이름 변경 및 이동 (dry_run) | ✅ |
| **ProcList** | 프로세스 목록 — PID, 이름, 커맨드라인, 메모리. 민감 인자 자동 마스킹. 이름/포트 필터 | ✅ |
| **ProcKill** | PID/포트로 프로세스 종료/일시정지/재개. 트리 킬, 시그널 선택(kill/term/hup/int/stop/cont), 좀비 처리(Linux), dry_run | ✅ |
| **ProcExec** | 에이전트를 붙잡지 않는 프로세스 실행. `yield_after_sec` 안에 안 끝나면 `job_id` 반환(wait/status/tail/cancel/list, 프로세스 트리 종료), 출력을 계속 수집하는 백그라운드 job, 일시정지 상태 시작, 수명 타임아웃·환경변수, 안전한 반복 진단 압축과 만료형 raw 출력 조회 | ✅ |
| **SSH** | 기본 32K head+tail 캡처, 원본 바이트 수, 비정상 종료 오류 의미론, 백그라운드 작업(start/wait/status/tail/cancel, `toolbox operation=job`에서도 조회), 비영어 Windows에서도 UTF-8 `powershell_script` 출력. 인증 인식 풀링, 호스트 키 검증, ProxyJump, IPv6 | ✅ |
| **SSHKey** | 로컬 개인키를 PuTTY PPK v3, 전통 PEM, 최신 OpenSSH, PKCS#8 사이에서 변환. 입력 자동 감지, 암호화 PPK/OpenSSH 출력, 0600 저장을 지원하며 키 본문은 반환하지 않음 | ✅ |
| **SFTP** | SSH 경유 파일 전송 및 원격 파일시스템 관리. 업로드, 다운로드, ls, stat, mkdir, rm, chmod, rename. 비동기 전송(upload_async/download_async + status/cancel). SSH 세션 풀 재사용. 최대 2GB | ✅ |
| **Bash** | 영속 셸 세션 — 작업 디렉토리·환경변수 상태 유지, 안전한 반복 진단 압축과 만료형 raw 출력 조회. 세션 풀링 (최대 5개, 유휴 타임아웃 30분). Unix: bash/sh, Windows: PowerShell/git-bash/cmd | ✅ |
| **Download** | URL에서 파일 다운로드. ECH + DoH 기본 활성. SSRF 차단. HTTP/SOCKS5 프록시. 원자적 파일 저장. 최대 2GB | ✅ |
| **HTTPReq** | HTTP 요청 실행 (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS). 커스텀 헤더, 본문, 프록시 지원. API 테스트용. SSRF 차단 | ✅ |
| **Query** | JSON/YAML/TOML 파일에서 점 표기법 경로로 값 하나만 조회 (예: `dependencies.react`, `services.web.ports[0]`, `users[*].email`). 형식은 확장자 또는 `format`으로 지정. 큰 설정 파일의 토큰 절약 | ✅ |
| **Copy** | 파일/디렉토리 복사. 원자적 쓰기 + 권한 보존. 재귀 디렉토리 복사. Windows 잠긴 파일 폴백 (실행 중인 exe/DLL 이름 변경 후 교체). dry_run 미리보기 | ✅ |
| **Mkdir** | 디렉토리 생성. 8진수 권한 모드 지정 가능 (예: 0755). 기본 재귀 생성 (mkdir -p). dry_run 미리보기 | ✅ |
| **MultiRead** | 최대 50개 파일, 호출 전체 32K 예산, 파일별 기본 200줄, 초장문 행 안전 처리, 파일별/전체 continuation 메타데이터. 해시는 opt-in | ✅ |
| **RegexReplace** | 파일/디렉토리 전체 정규식 찾기-바꾸기. 인코딩과 줄바꿈 보존, 캡처 그룹 ($1, $2) 지원. 바이너리 파일 자동 제외. dry_run 미리보기 | ✅ |
| **NetCheck** | 네트워크 진단: `external_ip`(공인 IPv4/IPv6, 제공자 자동 fallback), `dns`(A/AAAA/MX/CNAME/TXT/NS/SOA, DoH 또는 시스템 리졸버), `tls`(인증서 주체·발급자·만료일·SAN·TLS 버전·암호 스위트), `port`(TCP 포트 OPEN/CLOSED와 응답 시간) | ✅ |
| **MySQL** | MySQL/MariaDB SQL 쿼리 실행. SELECT 결과의 행·열·셀·전체 출력 제한을 각각 설정 가능하고 DML은 영향 행 수 반환. 페이징은 SQL LIMIT/OFFSET 사용 | ✅ |
| **Redis** | Redis 명령 실행. 타입별 포맷 출력. TLS 지원. 위험 명령(FLUSHALL, SHUTDOWN 등) 차단 | ✅ |
| **SLOC** | 언어별 소스 코드 라인 수 집계. 70+ 언어 감지, 파일/언어별 분류, 빈 줄 통계, max_depth 제어 | ✅ |
| **Debug** | DAP(Debug Adapter Protocol) 기반 인터랙티브 디버거. 변수값·전체 출력 제한과 variables/completions/modules/loaded_sources 페이징 지원. dlv(Go), debugpy(Python), codelldb(C/C++/Rust) 테스트 완료. 모든 DAP 호환 어댑터 사용 가능. Stdio/TCP 모드. 참고: vsdbg(Microsoft)는 VS Code 라이센스 필수로 단독 사용 불가 — codelldb 또는 netcoredbg를 대안으로 사용 | ✅ |
| **Analyze** | PE/ELF/Mach-O 정적 바이너리 분석·리버스 엔지니어링. x86/x64 PE·ELF 함수를 C로 디컴파일하며 일치하는 PDB, 내장 DWARF, IL2CPP 메타데이터의 이름과 타입을 적용([상세](#디컴파일)). x86/x64/ARM/ARM64 디스어셈블, 상수를 호출 인자까지 추적하는 시맨틱 명령어 검색, 주소·문자열·구조체 필드 xref, 함수 경계와 호출 그래프, RTTI·vtable·포인터·구조체 레이아웃, 헤더 파싱, imphash, Rich 헤더, DWARF, 문자열, hexdump, 패턴 검색, 엔트로피, 오버레이 탐지, 바이너리 diff, 영구 사용자 주석. `strings`·`entropy`·`bin_diff`만 `max_file_size_mb` 제한 적용 | ✅ |
| **Memtool** | CheatEngine 스타일 프로세스 메모리 도구 — 메모리 값 검색/필터/읽기/쓰기, read_chain(base+offset 포인터 체인을 한 콜에 배치로 해소), 라이브 디스어셈블리(x86/x64/ARM/ARM64), 실행 취소, 구조체 패턴 검색, 포인터 스캔, 메모리 diff. 대용량 스캔을 위한 디스크 기반 스냅샷. 세션 관리 (유휴 타임아웃). Windows, Linux 지원. Windows는 elevated 시 SeDebugPrivilege 자동 활성화, opt-in `force_dacl`로 같은 유저의 self-harden DACL 프로세스 우회(원본 DACL 원복). 긴 스캔은 `job_id`로 yield되고 cancel 시 즉시 멈춤(취소된 filter는 롤백) | ✅ |
| **Wintool** | Windows GUI 자동화 -- 창/자식 컨트롤 검색/열거, 스크린샷 캡처(ImageContent PNG), 클립보드 이미지 읽기, 텍스트 읽기/쓰기, 클릭, 타이핑, 원시 메시지 전송, 표시/숨기기/최소화/최대화, 이동/크기 변경, 닫기, 포커스. screenshot/clipboard 기본 ImageContent 반환 (save_path 옵션으로 파일 저장). AI 에이전트가 GUI 앱을 "보고" 조작할 수 있게 함. Windows 전용 | ✅ |
| **CodeGraph** | C/C++·Python·Go·C#·Rust·Java용 시맨틱 코드 그래프. 심볼 정의, 호출자/피호출자, 호출 트리, 클래스 메서드와 상속, importer, 미사용 심볼을 단일 프로젝트나 multi-root workspace에서 조회. overload, virtual/interface dispatch, alias, 전이 include 해석. 완전 내장형이라 컴파일러·언어 서버·외부 바이너리 불필요 | ✅ |
| **SetConfig** | 런타임 설정 변경 (인코딩, 파일 크기 제한, symlink, workspace 등) | ✅ |
| **Help** | 에이전트용 내장 사용법 안내. 분량이 큰 `tools`·`analyze`는 목차를 돌려주고 섹션 단위(`analyze/decompile`)로 조회 | ✅ |

## 디컴파일

`analyze(operation="decompile")`는 x86/x64 PE·ELF 함수를 C로 디컴파일합니다. 엔진은 Ghidra 디컴파일러 코어의 Go 포트인 Gosleigh(현재 v0.1.19)입니다.

```json
{"operation":"decompile","file_path":"game.exe","va":"Player::TakeDamage, 0x140001000"}
```

- 일치하는 PDB나 내장 DWARF를 자동 적용해 함수 이름, 프로토타입, 구조체/enum 타입, 전역, 지역변수를 복원합니다. 함수가 쓰는 타입 정의는 C 뒤에 출력하고, 그 밖의 타입은 `type_info`로 조회합니다.
- 난독화되거나 손상된 함수도 출력합니다. 디코딩할 수 없는 경로는 `halt_baddata()`로 끝나고, 폭주하는 흐름은 함수의 `.pdata` 범위에서 잘리며, 런타임 트레이스로 확인한 조건 분기는 `assume_branches`로 고정합니다.
- 호출마다 시간·메모리 제한이 걸린 워커 프로세스에서 실행합니다. 로드된 워커는 10분간 재사용되어 같은 바이너리의 후속 호출은 로드를 건너뜁니다.
- `agent-tool decompile-all <binary>`는 모든 함수를 JSONL 코퍼스로 덤프합니다.

에이전트용 operation별 안내: `agent_tool_help` 토픽 `analyze/decompile`.

## IL2CPP 프로토타입

Windows x64 IL2CPP 이미지에 PDB/DWARF가 없으면 `decompile`이 `il2cpp_signatures`에서 프로토타입을 가져옵니다. `global-metadata.dat`(메타데이터 v39는 DLL 실행이나 외부 덤퍼 없이 직접 읽음), Il2CppDumper `script.json`, 내보낸 `methodsigs.tsv`를 받습니다. 바이너리 옆 사이드카와 표준 Unity 메타데이터 위치는 자동으로 찾고, `none`으로 끌 수 있습니다. 디버그 정보가 우선하며 이름은 바꾸지 않습니다.

상세: [내장 추출, 탐색 규칙, TSV 형식](docs/il2cpp.ko.md), [클래스·가상 슬롯 타입 내보내기](docs/il2cpp-types.md).

## 분석 주석 저장

`analyze`는 명령어, 함수, 디컴파일된 C 줄에 붙인 사용자 라벨과 코멘트를 SQLite 파일에 보관합니다(`annotation_set`, `annotation_list`, `annotation_delete`, `annotation_batch`, `annotation_suggest`). 디스어셈블과 디컴파일 출력에 저장된 주석이 자동으로 표시되며 엔진이 낸 사실과 구분됩니다. 주석은 심볼 이름을 바꾸거나 타입을 덮어쓰지 않습니다.

```json
{"operation":"annotation_set","file_path":"sample.exe","rva":"0x1234","subject":"rax","comment":"User pointer returned here","annotations_path":"project.annotations.sqlite"}
{"operation":"disassemble","file_path":"sample.exe","va":"0x140001234","annotations_path":"project.annotations.sqlite"}
```

- 주석은 바이너리의 SHA-256과 정적 주소로 구분합니다. 복사본은 주석을 유지하고, 수정된 빌드는 물려받지 않습니다.
- 수정과 삭제는 revision을 확인합니다. 오래된 revision이면 레코드를 바꾸지 않고 실패합니다.
- C 줄 주석은 디컴파일 스냅샷에 묶입니다. C가 바뀌면 검토 대상으로 남고 `annotation_suggest`가 옮길 위치를 제안합니다.
- 비공개 주석 DB는 공개 Git 이력에 넣지 마세요(이 저장소는 `*.annotations.sqlite*`를 무시합니다).

필드, revision 규칙, 일괄 저장 사용법은 `agent_tool_help` 토픽 `analyze/annotation_set`, `analyze/annotation_batch`에 있습니다.

## 핵심 개선사항

### 스마트 들여쓰기
LLM은 보통 공백으로 출력하지만, 많은 프로젝트가 탭을 사용합니다. AgentTool은 파일의 기존 스타일에 맞게 들여쓰기를 자동 변환합니다.

- 부모 `.editorconfig`의 `indent_style`, `indent_size`, `tab_width`를 속성별로 상속. `root = true`, `unset`, `indent_size=tab`과 흔한 `**` 경로 패턴 반영
- 설정이 없으면 파일 내용(최대 8 MiB, LF·CRLF·CR)으로 감지. 연속 줄 정렬·주석·문자열이 아니라 블록 구조로 너비를 판정
- 기존 공백 들여쓰기가 탭 설정과 충돌하면 파일에서 감지한 공백 너비 유지
- 탭↔공백과 2칸↔4칸 등의 공백 너비 변환 지원. 변환한 검색 문자열도 줄 경계를 지키며, 탭 깊이 보정 시 상대 중첩 유지
- 유일한 한 줄·여러 줄 블록의 실제 들여쓰기와 접두 공백 대응을 활용하여 혼합 파일의 소수 스타일, 정렬, 빈 줄의 들여쓰기 보존. 블록의 상대 중첩 구조는 일치해야 함
- C++·헤더와 Python 파일은 내장 Tree-sitter 엔진이 감싸는 블록을 보고 새 중첩 단계의 들여쓰기를 추정
- 치환 문자열에서 토큰 열에 맞춘 정렬과 여러 줄 문자열·주석 내부는 입력한 그대로 보존
- 동일하게 타당한 탭 깊이 후보가 여러 개면 임의로 선택하지 않고 오류 반환
- 감지는 언어 포매터가 아닌 추정 방식이므로, 자동 편집 결과는 `dry_run=true`로 검토 가능

### 인코딩 보존
UTF-8로 강제 변환하지 않고, 원본 파일 인코딩을 유지합니다.

- **감지 우선순위**: BOM → 호출별 `encoding` 지정 → 상속된 `.editorconfig` charset → BOM 없는 UTF-16 → 유효한 UTF-8 → chardet 자동 감지 → 폴백 인코딩
- **지원 인코딩**: UTF-8, UTF-8 BOM, EUC-KR, Shift-JIS, ISO-8859-1, UTF-16 (LE/BE, BOM 유무 무관) 등
- **설정 상속**: `charset`은 들여쓰기 설정과 독립적으로 상속. 새 파일의 `charset = utf-8-bom` 설정은 실제 UTF-8 BOM 기록에 반영
- **디코딩 실패**: 잘못된 UTF-8·UTF-16, 감지된 손실성 디코딩, 지원하지 않는 인코딩은 오류 반환. `write`는 기존 파일의 인코딩을 읽을 수 없으면 덮어쓰기 거부
- **설정 변경 없이 재시도**: `read`, `multiread`, `edit`, `multiedit`, `write`, `patch`, `file_info`에 `encoding="EUC-KR"`, `encoding="CP949"` 등 지원하는 인코딩 지정 가능. `.editorconfig`보다 우선하며 기존 BOM은 유지. 의도적인 인코딩 변환은 `convert_encoding` 사용
- **감지 한계**: 자동 감지는 추정 방식이며, 긴 헤더 뒤의 레거시 텍스트를 놓치지 않도록 ASCII 머리말 이후부터 64 KiB 표본을 사용. 결과가 모호하면 `encoding` 또는 `charset` 명시
- **ASCII 오탐 경고 없음**: 유효한 UTF-8 은 직접 검증하므로 순수 ASCII 파일에 신뢰도 경고가 뜨지 않음
- **줄바꿈**: LF, CRLF, CR, 혼합 파일을 구분. `edit`은 CRLF/LF 어느 쪽이든 여러 줄 `old_string`을 매칭하며(둘이 섞인 파일 포함), `edit`/`regexreplace`로 삽입되는 문자열은 해당 위치 구역의 줄바꿈을 따라가므로 나머지 바이트는 그대로 유지됨

### 일관된 읽기와 묶음 편집

- `read`, `multiread`, `file_info`, `grep`, `patch`가 LF·CRLF·CR 줄 경계를 동일하게 처리. 끝 개행은 가짜 줄을 만들지 않으며, EOF 뒤를 읽으면 0줄 반환.
- 읽기 해시는 표시한 텍스트와 같은 원본 바이트에서 계산. `edit`, `multiedit`, `write`, `patch`, `regexreplace`, `convert_encoding`은 저장 전에 읽었던 원본의 해시를 다시 확인. `expected_hash`는 `edit`, `multiedit`, `patch`에서 지정 가능.
- `multiedit`도 `edit`과 같은 `encoding`·`indent_style` 옵션 지원. 각 치환은 앞선 결과를 대상으로 하며, 중간 치환 실패 시 파일 전체를 그대로 유지.
- `multiread`는 전역·파일별 `encoding` 지원. 원래 입력 목록에 `start_file_index=next_file_index`, `resume_offset=next_offset`을 지정해 이어 읽기(오프셋이 0이면 생략). 현재 파일의 최초 요청 끝과 뒤쪽 파일의 원래 요청 범위 유지.
- 읽기 출력 예산은 256~131072자. 첫 줄이 예산보다 길면 잘렸음을 표시하고 다음 줄로 진행하며, 전체 줄을 보려면 `max_output_chars` 또는 `max_line_chars` 확대.

### 변환과 대량 처리 결과

- 디렉토리 `regexreplace`는 `files_scanned`, `error_count`, `limit_reached`, `truncated`로 결과와 일치 파일 한도를 명시. 다른 파일이 실패해도 성공한 변경은 유지되므로 부분 결과를 확인하고 실패한 파일만 재시도.
- `diff`는 `encoding_a`·`encoding_b`와 `context_lines=0` 지원. 해석된 텍스트가 같은 경우와 원본 바이트가 같은 경우를 구분하며, CR·LF 배치 차이와 마지막 개행 누락도 따로 표시.
- `convert_encoding`의 `from_encoding`으로 원본 인코딩 지정 가능. GBK와 GB18030은 서로 다른 대상이며 GB2312는 GBK 호환 별칭. 대상 인코딩이 표현하지 못하는 문자가 있으면 원본 유지.
- 파일 쓰기는 대상 옆에 교체 파일을 준비. 준비·교체 실패 시 원본을 직접 잘라 쓰는 방식으로 우회하지 않고 오류 반환. 대상을 잠근 프로그램을 닫거나 디렉토리 권한을 확인한 후 재시도.

### 토큰을 보호하는 디렉토리 목록
`listdir`는 기본적으로 페이지당 500개까지만 반환하고, 항목이 더 있으면
`next_cursor`를 제공합니다. `directories_only`, `files_only`, `name_pattern`
(예: `A*`) 또는 여러 OR 패턴을 받는 `include`로 결과를 좁힐 수 있습니다.
이름이 필요 없으면 `counts_only=true`로 파일/디렉토리 개수만 반환합니다.

### 유휴 메모리 반환
툴 호출 없이 30분이 지나면 서버가 힙을 OS에 반환합니다. 50MB 파일을 한 번 읽은
인스턴스가 200MB를 계속 쥐지 않고 기준선인 약 20MB로 돌아갑니다. 유휴 상태라고
종료하지는 않습니다. stdio 서버는 버려진 클라이언트와 조용한 클라이언트를 구분할
수 없기 때문입니다. 열려 있는 shell/ssh 세션은 그대로 유지됩니다.

## 빠른 시작

1. [Releases](https://github.com/knewstimek/agent-tool/releases/latest)에서 OS에 맞는 바이너리 다운로드
2. `agent-tool install` 실행 (또는 `agent-tool install claude` 등 특정 에이전트)
3. IDE / 에이전트 재시작
4. 끝 — core 도구는 즉시 사용하고 나머지는 `toolbox` gateway로 필요할 때 호출 가능

또는 AI 에이전트에게 시키세요:
> "https://github.com/knewstimek/agent-tool/releases/latest 에서 agent-tool을 다운받고 `agent-tool install` 실행해줘"

Claude Code, Codex 등 AI 코딩 에이전트가 다운로드 → 설치 → 재시작까지 알아서 처리합니다.

### 권장: 에이전트에게 agent-tool 우선 사용 지시

설치 후 에이전트가 agent-tool을 사용할 수 있게 되지만, 기본 내장 도구(Read, Edit 등)를 계속 쓸 수 있습니다. 에이전트가 agent-tool을 **우선 사용**하게 하려면 아래 지시를 추가하세요.

**코드 탐색 팁**: 대규모 프로젝트에서 AST 기반 코드 탐색을 사용하려면 CLAUDE.md / AGENTS.md에 추가하세요:

```
At the start of a session, run codegraph(op="index", path="<project_root>") to build a code index.
여러 저장소를 하나의 그래프로 만들 때는 codegraph(op="index", path="<db_root>", roots=["<source_root_1>", "<source_root_2>"])를 사용하세요. source-root provenance가 다른 프로젝트의 동명 심볼 오염을 막고, 명시적·전이 include는 root 사이에서도 연결합니다.
Then use codegraph for structural queries (find, callers, callees, methods, inherits) instead of grep.
```

**Strict** 또는 **Soft** 선택:

| 모드 | 사용 시점 | 지시문 |
|------|----------|--------|
| **Strict** | 비 UTF-8 파일이나 혼합 들여쓰기 프로젝트 | `ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools. agent-tool preserves file encoding and respects .editorconfig indentation settings.` |
| **Soft** | 일반 프로젝트 | `Prefer agent-tool MCP tools (mcp__agent-tool__*) over built-in file tools when available.` |

**어디에 넣을까:**

<details>
<summary><b>Claude Code</b> — CLAUDE.md (프로젝트별) 또는 전역 설정</summary>

**프로젝트별** — 프로젝트의 `CLAUDE.md`에 추가:
```
ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools.
```

**전역** (모든 프로젝트) — `~/.claude/CLAUDE.md`에 추가:
```
ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools.
```

**강제 적용** — `~/.claude/settings.json`으로 내장 도구를 권한 레벨에서 차단:
```json
{
  "permissions": {
    "deny": ["Read", "Edit", "MultiEdit", "Write", "Glob", "Grep"]
  }
}
```
Claude Code의 내장 파일 도구를 아예 사용 불가 상태로 만들어 에이전트가 agent-tool을 쓰도록 강제합니다. 프롬프트 지시에 의존하지 않고 확실히 적용하고 싶을 때 권장.
</details>

<details>
<summary><b>Codex CLI</b> — model_instructions.md (전역)</summary>

1. `~/.codex/config.toml`에 추가 (최상위 레벨, `[mcp_servers.*]` 안이 **아님**):
```toml
model_instructions_file = "~/.codex/model_instructions.md"
```

2. `~/.codex/model_instructions.md` 파일 생성:
```
ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools.
```

3. Codex 재시작.

**프로젝트별** — 프로젝트의 `AGENTS.md`에 추가해도 됩니다.
</details>

<details>
<summary><b>Cursor / Windsurf / Cline</b> — .cursorrules 또는 AGENTS.md</summary>

프로젝트의 `.cursorrules`, `.windsurfrules`, 또는 `AGENTS.md`에 추가:
```
ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools.
```
</details>

## 설치

### 자동 설치 (권장)

```bash
# 감지된 모든 에이전트에 자동 등록 (전체 자동 승인 — 모든 도구)
agent-tool install

# Safe 모드 — 로컬 파일 도구만 자동 승인 (SSH, HTTP, DB, 셸 제외)
agent-tool install --safe-approve

# 자동 승인 없음 — 모든 도구 호출에 수동 승인 필요
agent-tool install --no-auto-approve

# 특정 에이전트에만 등록
agent-tool install claude
agent-tool install claude --safe-approve

# 선택 사항인 에이전트 스킬도 함께 설치 (Claude Code, Codex)
agent-tool install --skills

# 제거 (agent-tool 항목만 삭제, 다른 설정은 보존)
agent-tool uninstall          # 모든 에이전트에서 제거
agent-tool uninstall claude   # 특정 에이전트에서만 제거
```

**설치 권한 수준:**

| 수준 | 플래그 | 자동 승인 도구 |
|------|--------|----------------|
| Full (기본) | _(없음)_ | 모든 도구 (`mcp__agent-tool__*` 와일드카드) |
| Safe | `--safe-approve` | 29개 로컬 전용 도구 (read, edit, write, grep, glob 등) — SSH, HTTP, DB, bash, 프로세스 제어 제외 |
| None | `--no-auto-approve` | 없음 — 모든 호출에 수동 승인 필요 |

승인 수준과 스키마 프로필은 별개입니다. 전체 네임스페이스를 승인해도 서버는
토큰 효율적인 `core` 프로필로 시작할 수 있습니다.
`toolbox`의 `operation=call`은 네트워크·셸·DB·프로세스 제어 도구도 호출할 수
있으므로 `--safe-approve` 자동 승인 대상에서 의도적으로 제외됩니다. Safe 모드에서는
toolbox 승인을 매번 검토하고, 전체 AgentTool 네임스페이스를 신뢰하려는 경우가 아니면
영구 허용하지 마세요.

### 에이전트 스킬 (선택)

[`skills/`](skills) 폴더에는 에이전트에게 도구를 *어떤 순서로 쓸지* 알려주는 작업 흐름 스킬이 들어 있습니다. 파라미터 레퍼런스는 내장 help가 계속 맡습니다.

| 스킬 | 용도 |
|------|------|
| [`agent-tool-reversing`](skills/agent-tool-reversing/SKILL.md) | `analyze`, `memtool`, `debug`를 쓰는 리버스 엔지니어링: 바이너리에서 어디부터 볼지, 디컴파일과 디스어셈블을 언제 쓸지, 난독화된 함수 처리, 런타임 확인, 발견한 내용을 주석으로 저장 |

`agent-tool install --skills`가 `~/.claude/skills`와 `~/.codex/skills`에 복사합니다. 스킬은 바이너리에 내장되어 있어 레포를 받을 필요가 없습니다. 에이전트는 설치된 스킬의 설명을 매 세션에 불러오므로 기본 설치에는 포함하지 않았습니다. 한 번 설치하면 이후 `install`/`reinstall`이 최신으로 갱신하고 `uninstall`이 제거합니다. 직접 설치하려면 스킬 폴더를 에이전트의 스킬 디렉터리에 복사하면 됩니다.

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
# 초기 스키마 프로필 선택 (기본: core)
agent-tool --profile core-lite

# core에 선택한 도구만 추가 노출
agent-tool --profile core+copy+delete+ssh+wintool

# UTF-8이 아닌 프로젝트에서 폴백 인코딩 지정
agent-tool --fallback-encoding EUC-KR
```

프로필: `core-lite`(read/write/edit/grep/toolbox), `core`(11개 스키마),
`coding`, `remote`, `analysis`, `full`.
프리셋에 `+도구명`을 붙여 초기 목록을 조합할 수 있습니다.
`core+copy+delete+ssh+wintool`은 15개를 노출하며 분석·기타 원격 도구는
게이트웨이로 사용합니다. `AGENT_TOOL_PROFILE`과 toolbox `operation=profile`도
같은 구문을 지원합니다. 알 수 없는 도구나 빈 구성 요소가 있으면 등록 전에 거부합니다.
실행 중에는 클라이언트와 무관하게 동작하는 `toolbox` gateway를 우선 사용합니다.
`operation=describe`는 한 도구의 스키마를 반환하며 `compact=true`와
`tool_operation`을 함께 쓰면 한 operation으로 제한합니다. 반환된 `schema_handle`을
다시 전달하면 변경 없는 스키마의 재출력을 피할 수 있습니다. `operation=call`은 고정된
toolbox binding을 통해 그 도구를 호출합니다. 명령 진단이 압축된 경우에는
`operation=output`과 표시된 ID로 보존된 bounded raw 출력을 30분 동안 조회할 수
있으며 큰 출력은 `next_offset`으로 이어 읽습니다.
오래 걸리는 호출은 에이전트를 붙잡지 않습니다. `bash`, `ssh`, `sftp`, `download`,
`analyze`, `codegraph`, `memtool`은 호출이 약 15초를 넘기면(`procexec`은 `yield_after_sec` 후) 작업을 계속
돌린 채 `job_id`를 반환하므로, 그동안 에이전트가 사용자에게 답하거나 다른 일을 할 수 있습니다.
결과는 `operation=job`과 `job_action=wait|status|tail|cancel|list`로 받으며, wait를 취소해도
job은 멈추지 않습니다. `enable`, `disable`, `profile`은
`tools/list_changed`를 반영하는 클라이언트의 직접 binding 용도로 유지됩니다.

작업 목록·결과 조회·취소는 시작한 MCP 세션으로 제한하며 SSH·ProcExec·toolbox에
공통 적용합니다. ID를 알아도 다른 세션에서는 접근할 수 없습니다. 세션 종료가
백그라운드 작업을 중단하지는 않지만 새 세션에서 이전 세션의 작업 기록을 조회할 수는 없습니다.

### 환경변수

세션마다 CLI 플래그를 반복하지 않으려면 환경변수를 설정하세요:

```bash
# Windows (관리자 권한 불필요)
setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR
setx AGENT_TOOL_PROFILE coding

# Linux / macOS (~/.bashrc 또는 ~/.zshrc에 추가)
export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR
export AGENT_TOOL_PROFILE=coding
```

우선순위: CLI 플래그 > 환경변수 > 기본값 (UTF-8).

### 세션 디렉터리 별칭

`directory_alias`를 toolbox의 `describe` 후 `call`로 호출해 여러 디렉터리를 등록합니다.

```json
{"operation":"set","aliases":{"src":"src","logs":"logs"}}
{"operation":"set","connection_profile":"dev","aliases":{"deploy":"/srv/releases/current"}}
```

로컬 값은 존재하는 디렉터리의 작업공간 상대경로나 절대경로입니다. 원격 값은 절대경로이며
등록할 때 서버에 접속하지 않습니다. read·write·edit·copy·multiread 등 공통 로컬 경로에는
`@src/main.go`, SSH `remote_root`와 SFTP 경로에는 `@deploy`를 쓸 수 있습니다.
read 진단과 write·edit·copy·multiread 결과, SFTP 경로 표시는 재사용 가능한 별칭이 더
짧을 때 축약합니다. 다른 도구는 일반 경로 표시를 유지할 수 있습니다.
파일 내용과 SSH 명령문은 치환하지 않습니다.

별칭은 클라이언트 세션 메모리에만 저장하고 로컬 작업공간·원격 접속 대상별로 구분하며,
MCP 세션 종료 시 정리합니다. 별칭용 JSON 파일은 생성하거나 읽지 않습니다.
기존 SSH 접속 프로필은 원래 방식대로 읽습니다. `list`로 필요할 때만
조회(`names`로 필터)하고, `delete`의 `names`로 삭제합니다. 기존 값을 바꾸려면
`overwrite:true`가 필요합니다. 이름은 대소문자를 구분하는 ASCII 영숫자이며 두 번째
문자부터 `_`·`-`를 허용합니다. 이름은 64자, 범위별 별칭은 64개까지입니다.
미등록 이름과 절대경로 형태·`..`·`:`가 들어간 접미 경로는 거부합니다.
실제 파일명이 `@`로 시작하면 `./@name`을 쓰세요. 별칭은 경로 편의 기능이며
샌드박스가 아니므로 심볼릭 링크의 대상까지 제한하지는 않습니다.

MCP 호출마다 작업공간과 별칭 목록을 처음 사용할 때 한 번 확정합니다. 호출 도중
등록·변경된 별칭은 이후 호출에 적용해 여러 경로를 처리하는 작업이 서로 다른 버전을
섞지 않게 합니다. 파일명 공백은 의미가 있으므로 임의로 제거하지 않습니다.
SSH 포트·인증 기본값의 동등한 표현은 같은 대상 범위를 사용하며 호스트·자격 증명·
점프 설정이 다르면 계속 분리합니다.

SFTP 비동기 전송의 조회·취소는 시작한 MCP 세션에서만 가능합니다. 실제 경로를 보관하고
조회 시 현재 별칭으로 표시하므로, 별칭이 삭제되거나 바뀌었으면 원격 절대경로를 표시합니다.

### 암호화 접속 프로필

SSH·SFTP, MySQL, Cloudflare, AWS 자격 증명은 보관소에 등록하고 `profile_search`로 찾을 수 있습니다. 설정과 리비전 관리 방법은 `agent_tool_help(topic="tools/credential_vault")`를 참고하세요.

### 기존 로컬 SSH/SFTP 접속 프로필

SSH와 SFTP는 `connection_profile` 또는 세션 로컬 `connection_id`를 받아 host, user,
key, jump host 필드 반복을 없앨 수 있습니다. 기존 프로필은 OS 사용자 설정 디렉터리의
`agent-tool/connections.json`에서 읽으며 `AGENT_TOOL_CONNECTION_PROFILE_FILE`로 위치를
바꿀 수 있습니다. workspace 안에 둘 경우 반드시 명시적으로 ignore하고 로컬에만 보관하세요.

```json
{
  "connections": {
    "dev": {
      "host": "192.0.2.10",
      "user": "builder",
      "key_file": "/local/path/to/id_ed25519",
      "host_key_check": "strict",
      "trusted": true,
      "remote_root": "/srv/app"
    }
  }
}
```

첫 호출이 반환한 opaque `connection_id`는 두 도구에서 30분간 재사용할 수 있습니다.
로컬 프로필은 기본적으로 `trusted:true`이며, `trusted:false`를 지정하면 사설 주소 경고를
pooled connection당 한 번이 아닌 매 호출마다 표시합니다. 표시 방식만 바뀌며 SSRF 차단과
cloud metadata 보호는 그대로 유지합니다. SSH는 `quiet`,
`echo_command`, `result_only`도 지원하며 마지막 옵션은 `stdout`, `stderr`, `exit_code`
중심의 compact JSON을 반환합니다. SFTP는 `quiet`, `result_only`, 최대 100개 파일의
`upload_many`를 지원합니다.

접속 프로필이나 최초 SSH/SFTP 호출에 절대경로 `remote_root`를 지정하면, 반환된
`connection_id`로 원격 작업 디렉터리도 재사용합니다. SSH는 일반·백그라운드 명령과
PowerShell 스크립트 실행마다 해당 디렉터리로 이동하며, 이동에 실패하면 실행하지
않습니다. SFTP의 상대 `remote_path`, 이름 변경의 `new_path`, 일괄 업로드 대상도 이
루트를 기준으로 해석합니다. 명시적인 절대경로는 유지하며, 접근 범위를 제한하는
샌드박스는 아닙니다. 기존 ID에 다른 루트를 지정하면 원래 ID를 바꾸지 않고 새 ID를 반환합니다.

`remote_shell`은 SSH 서버의 기본 셸을 뜻하며 `posix`, `cmd`, `powershell`을 지원합니다.
생략하면 Windows 드라이브 루트(`D:/app`)에는 `cmd`, 나머지에는 `posix`를 적용합니다.
서버의 기본 셸이 다르면 명시적으로 지정하세요. Windows 루트는 드라이브 절대경로여야
하며, cmd에서 확장되거나 셸 구문으로 해석되는 특수문자가 있는 루트는 거부합니다.
`powershell_script`는 SSH 기본 셸과 별도로 PowerShell의 작업 디렉터리 설정을 사용합니다.

`remote_root`가 있는 Windows CMD 명령은 PowerShell의 프로세스 API로 작업 디렉터리를
지정하여 실행하므로 대상에 PowerShell이 필요합니다. 명령을 데이터로 전달해 괄호나
`%CD%`가 작업 디렉터리 설정 구문에 간섭하지 않게 합니다. PowerShell은 본문의 선두
`using`·`param` 선언을 보존하고 스크립트 바깥에서 위치를 설정합니다. 생성된 Windows
실행 명령의 최종 길이가 제한에 도달하면 임시 스크립트 실행 방식으로 전환합니다.

read 진단, multiread 헤더, edit·copy 결과의 로컬 경로는 작업공간 내부일 때 상대경로로
표시합니다. SFTP는 로컬 경로를 작업공간 기준, 원격 경로를 `remote_root` 기준으로
표시하며 비동기 전송 상태에도 적용합니다. 루트 밖의 경로는 그대로 표시합니다.
파일 내용과 SSH stdout·stderr는 바꾸지 않습니다. SSH 명령 재출력은 기본으로 끄며,
원래 명령을 표시하려면 `echo_command:true`를 지정합니다. 호출마다 루트 안내나 별칭
목록을 추가하지 않습니다.

```json
{"connection_profile":"dev","command":"git status"}
{"operation":"upload","connection_profile":"dev","local_path":"build/app","remote_path":"bin/app"}
```

프로필을 수정하지 않으려면 최초 호출에 루트를 지정하고 반환된 ID를 재사용합니다.

```json
{"connection_profile":"dev","remote_root":"/srv/app","command":"git status"}
{"operation":"ls","connection_id":"<returned-id>","remote_path":"logs"}
```

### 로컬 SSH 개인키 변환

`ssh_key`는 개인키 내용을 네트워크로 보내거나 응답에 노출하지 않고 로컬 파일을
변환합니다. 입력은 PPK, PEM, PKCS#8, OpenSSH 중 하나로 자동 감지하며 출력 형식은
`ppk`, `pem`, `pkcs8`, `openssh` 중 하나입니다.

```json
{
  "operation": "convert",
  "input_path": "server.pem",
  "output_path": "server.ppk",
  "output_format": "ppk",
  "input_passphrase": "",
  "output_passphrase": "",
  "overwrite": false
}
```

PPK 출력은 버전 3입니다. 패스프레이즈로 보호하는 PPK 출력은 Argon2id,
AES-256-CBC, HMAC-SHA-256을 사용하고, OpenSSH 출력은 최신 암호화 형식을 사용합니다.
전통 PEM과 PKCS#8 출력은 의도적으로 암호화하지 않으므로 출력 암호화가 필요하면
`openssh` 또는 `ppk`를 사용하세요. 새 파일은 0600 권한으로 저장하며
`overwrite=true`가 없으면 기존 파일을 바꾸지 않습니다.

### 런타임 설정

에이전트가 `set_config` 도구로 재시작 없이 설정을 변경할 수 있습니다:

| 파라미터 | 설명 | 기본값 |
|----------|------|--------|
| `fallback_encoding` | 자동 감지 실패 시 폴백 인코딩 | `UTF-8` |
| `encoding_warnings` | 인코딩 감지 경고 표시 | `true` |
| `max_file_size_mb` | read/edit/grep 최대 파일 크기 (MB) | `100` |
| `allow_symlinks` | tar 압축 해제 시 symlink 생성 허용 | `false` |
| `workspace` | 명시적 로컬 루트. 미설정 시 첫 MCP 클라이언트 root, 이후 cwd 사용 | _(MCP root/cwd)_ |
| `allow_http_private` | webfetch/download/httpreq의 사설 IP 접근 허용 | `false` |
| `allow_mysql_private` | mysql 도구의 사설 IP 접근 허용 | `true` |
| `allow_redis_private` | redis 도구의 사설 IP 접근 허용 | `true` |
| `allow_ssh_private` | ssh/sftp 도구의 사설 IP 접근 허용 | `true` |
| `enable_doh` | DNS over HTTPS 글로벌 활성화 (webfetch/download/httpreq/dnslookup) | `true` |
| `enable_ech` | Encrypted Client Hello 글로벌 활성화 (webfetch/download/httpreq) | `true` |

## 빌드

```bash
go build -trimpath -ldflags="-s -w" -o agent-tool .
```

크로스 컴파일:
```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o agent-tool .
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o agent-tool .
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o agent-tool.exe .
```

## 릴리스

보호된 GitHub workflow가 테스트, 선언된 전체 asset 빌드, MCPB/checksum 생성 및 업로드된
바이트 검증을 수행합니다. clean 상태로 push된 `master`에서 먼저 build-only dry-run을 실행합니다.

```powershell
.\scripts\release.ps1
```

dry-run 성공 후 `main.go`에 선언된 버전을 게시합니다.

```powershell
.\scripts\release.ps1 -Publish
```

workflow는 `docs/releases/vVERSION.md`의 추적된 릴리스 노트를 요구합니다. 게시 시 annotated
tag와 GitHub Release를 만들고, 최종 MCPB hash로 `server.json`을 갱신합니다.
RepoPlane이 이 저장소를 workspace로 사용할 때는 저장소 로컬 `catalog/` manifest를 통해 같은
dry-run, publish, status 작업을 검색하고 실행할 수 있습니다.

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

사용 가능 토픽: `overview`, `encoding`, `indentation`, `tools`, `debug`, `analyze`, `memtool`, `wintool`, `codegraph`, `troubleshooting`

분량이 큰 `tools`와 `analyze`는 전문 대신 짧은 목차(약 1k 토큰)를 돌려줍니다. 한 부분만 볼 때는 `topic/section`, 여러 개는 쉼표로 요청합니다:

```json
{ "tool": "agent_tool_help", "arguments": { "topic": "analyze/decompile" } }
{ "tool": "agent_tool_help", "arguments": { "topic": "tools/ssh,sftp" } }
```

## 보안

agent-tool은 강력한 시스템 접근 기능(SSH, MySQL, Redis, 파일 작업, HTTP 요청)을 제공합니다.
AI 코딩 에이전트와 함께 사용할 때 프롬프트 인젝션 위험에 유의하세요:

- **SSRF 보호**: 클라우드 메타데이터 IP (169.254.x.x, fe80::/10)는 설정과 무관하게 항상 차단됩니다. 사설 IP 접근은 프로토콜별로 `set_config`로 설정 가능 (`allow_http_private`, `allow_mysql_private`, `allow_redis_private`, `allow_ssh_private`)
- **DLP (데이터 유출 방지)**: 모든 HTTP 요청 본문에서 민감 데이터 패턴(PEM 개인키, AWS 액세스 키, GitHub/GitLab 토큰, Slack 토큰, .env 파일 덤프)을 스캔하고 **전송 전 차단**합니다
- **프롬프트 인젝션 경고**: 허용된 사설 IP 접속에는 짧은 경고를 표시하며, 신뢰된 로컬 SSH/SFTP 프로필은 pooled connection당 한 번만 표시합니다
- **Zip Slip 보호**: `../` 경로 조작을 통한 Path Traversal 차단 (zip, tar 모두)
- **Zip Bomb 보호**: 단일 파일 1GB, 총 추출 크기 5GB 제한
- **Symlink**: 기본 스킵 (보안). `set_config allow_symlinks=true`로 활성화 (tar만 지원). 활성화해도 outputDir 밖을 가리키는 symlink는 차단
- **파일 크기 제한**: 설정 가능한 최대 파일 크기 (기본 100MB)로 OOM 방지. `set_config max_file_size_mb=N`으로 조절 가능
- **인코딩 안전성**: chardet는 ASCII 머리말 이후의 64 KiB 표본을 사용하며, 잘못된 입력은 편집 결과가 손실된 텍스트로 저장되기 전에 오류로 알림

보안을 위해 AI 에이전트의 도구 호출을 승인 전에 검토하세요. 특히 SSH 명령, 외부 URL로의 HTTP 요청, 데이터베이스 쿼리에 주의가 필요합니다.

## 기술 스택

- **언어**: Go
- **MCP SDK**: [github.com/modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
- **인코딩**: saintfish/chardet + golang.org/x/text
- **배포**: 단일 바이너리 (크로스 컴파일)
- **디컴파일러**: [Gosleigh](https://github.com/knewstimek/gosleigh) + Ghidra x86/x64 언어 스펙 내장
- **PDB**: [gopdb](https://github.com/knewstimek/gopdb) (PDB 7.0 리더 + MSVC 디맹글러)

## 라이선스

[MIT](LICENSE)

디컴파일러(Gosleigh)와 내장된 Ghidra 언어 스펙은 Apache License 2.0을 따릅니다. Gosleigh는 미국 국가안보국(NSA)이 개발한 Ghidra 디컴파일러(https://github.com/NationalSecurityAgency/ghidra)의 재구현입니다.
