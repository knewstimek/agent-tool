package install

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type agentConfig struct {
	name       string
	configPath string
	format     string // "json" or "toml"
	jsonKey    string // JSON 설정 내 MCP 서버 키
}

// getAgents는 지원 에이전트 목록을 반환한다.
// 홈 디렉토리 조회 실패 시 에러를 반환한다.
func getAgents() (map[string]agentConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("홈 디렉토리를 가져올 수 없음: %w", err)
	}
	return map[string]agentConfig{
		"claude": {
			name:       "Claude Code",
			configPath: filepath.Join(home, ".claude", "settings.json"),
			format:     "json",
			jsonKey:    "mcpServers",
		},
		"cursor": {
			name:       "Cursor",
			configPath: filepath.Join(home, ".cursor", "mcp.json"),
			format:     "json",
			jsonKey:    "mcpServers",
		},
		"windsurf": {
			name:       "Windsurf",
			configPath: filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
			format:     "json",
			jsonKey:    "mcpServers",
		},
		"codex": {
			name:       "Codex CLI",
			configPath: filepath.Join(home, ".codex", "config.toml"),
			format:     "toml",
		},
	}, nil
}

// Run은 install 명령을 실행한다.
// target이 빈 문자열이면 감지된 모든 에이전트에 등록한다.
func Run(target string) error {
	agents, err := getAgents()
	if err != nil {
		return err
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("실행 파일 경로를 가져올 수 없음: %w", err)
	}
	// 심볼릭 링크 해결
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("경로 해석 실패: %w", err)
	}

	if target != "" {
		agent, ok := agents[strings.ToLower(target)]
		if !ok {
			return fmt.Errorf("알 수 없는 에이전트: %s (지원: claude, cursor, windsurf, codex)", target)
		}
		return installForAgent(agent, exePath)
	}

	// 모든 에이전트에 설치 시도
	installed := 0
	for _, agent := range agents {
		dir := filepath.Dir(agent.configPath)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue // 이 에이전트는 설치되지 않음
		}
		if err := installForAgent(agent, exePath); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] 실패: %v\n", agent.name, err)
		} else {
			installed++
		}
	}

	if installed == 0 {
		fmt.Println("감지된 에이전트가 없습니다. 대상을 지정해주세요: agent-tool install [claude|cursor|windsurf|codex]")
	}
	return nil
}

// Uninstall은 지정된 에이전트(또는 모든 에이전트)에서 agent-tool을 제거한다.
func Uninstall(target string) error {
	agents, err := getAgents()
	if err != nil {
		return err
	}

	if target != "" {
		agent, ok := agents[strings.ToLower(target)]
		if !ok {
			return fmt.Errorf("알 수 없는 에이전트: %s (지원: claude, cursor, windsurf, codex)", target)
		}
		return uninstallFromAgent(agent)
	}

	// 모든 에이전트에서 제거 시도
	removed := 0
	for _, agent := range agents {
		if _, err := os.Stat(agent.configPath); os.IsNotExist(err) {
			continue
		}
		if err := uninstallFromAgent(agent); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] 실패: %v\n", agent.name, err)
		} else {
			removed++
		}
	}

	if removed == 0 {
		fmt.Println("등록된 에이전트가 없습니다.")
	}
	return nil
}

func uninstallFromAgent(agent agentConfig) error {
	// Claude Code: 'claude mcp remove' 우선 시도
	if agent.name == "Claude Code" {
		removeClaudePermission()
		if err := uninstallClaudeMCPRemove(); err == nil {
			return nil
		}
		fmt.Println("[Claude Code] 'claude' CLI를 찾을 수 없습니다. settings.json에서 직접 제거합니다.")
	}

	switch agent.format {
	case "json":
		return uninstallJSON(agent)
	case "toml":
		return uninstallTOML(agent)
	default:
		return fmt.Errorf("지원하지 않는 설정 형식: %s", agent.format)
	}
}

// uninstallClaudeMCPRemove는 'claude mcp remove' CLI 명령으로 제거한다.
func uninstallClaudeMCPRemove() error {
	claudePath, err := exec.LookPath("claude")
	if err != nil {
		return err
	}

	cmd := exec.Command(claudePath, "mcp", "remove", "agent-tool")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("claude mcp remove 실패: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	fmt.Printf("[Claude Code] 제거 완료 (claude mcp remove)\n")
	return nil
}

func uninstallJSON(agent agentConfig) error {
	data, err := os.ReadFile(agent.configPath)
	if err != nil {
		return fmt.Errorf("설정 파일 읽기 실패: %w", err)
	}

	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("설정 파일 파싱 실패: %w", err)
	}

	servers, ok := config[agent.jsonKey].(map[string]any)
	if !ok {
		fmt.Printf("[%s] agent-tool이 등록되어 있지 않습니다.\n", agent.name)
		return nil
	}

	if _, exists := servers["agent-tool"]; !exists {
		fmt.Printf("[%s] agent-tool이 등록되어 있지 않습니다.\n", agent.name)
		return nil
	}

	// agent-tool 키만 제거 (다른 MCP 서버는 유지)
	delete(servers, "agent-tool")
	config[agent.jsonKey] = servers

	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON 직렬화 실패: %w", err)
	}

	if err := os.WriteFile(agent.configPath, output, 0644); err != nil {
		return fmt.Errorf("설정 파일 쓰기 실패: %w", err)
	}

	fmt.Printf("[%s] 제거 완료: %s\n", agent.name, agent.configPath)
	return nil
}

func uninstallTOML(agent agentConfig) error {
	data, err := os.ReadFile(agent.configPath)
	if err != nil {
		return fmt.Errorf("설정 파일 읽기 실패: %w", err)
	}

	content := string(data)
	if !strings.Contains(content, "[mcp_servers.agent-tool]") {
		fmt.Printf("[%s] agent-tool이 등록되어 있지 않습니다.\n", agent.name)
		return nil
	}

	// 섹션 제거 (install과 동일한 로직)
	lines := strings.Split(content, "\n")
	var result []string
	skip := false
	for _, line := range lines {
		if strings.TrimSpace(line) == "[mcp_servers.agent-tool]" {
			skip = true
			continue
		}
		if skip {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") && !strings.Contains(trimmed, "=") {
				skip = false
			}
		}
		if !skip {
			result = append(result, line)
		}
	}

	content = strings.TrimRight(strings.Join(result, "\n"), "\n") + "\n"
	if err := os.WriteFile(agent.configPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("설정 파일 쓰기 실패: %w", err)
	}

	fmt.Printf("[%s] 제거 완료: %s\n", agent.name, agent.configPath)
	return nil
}

func installForAgent(agent agentConfig, exePath string) error {
	// Claude Code: 'claude mcp add' 우선 시도 (CLI + VSCode 확장 모두 지원)
	if agent.name == "Claude Code" {
		if err := installClaudeMCPAdd(exePath); err == nil {
			return nil
		}
		// claude CLI가 없으면 settings.json 직접 수정으로 폴백
		fmt.Println("[Claude Code] 'claude' CLI를 찾을 수 없습니다. settings.json에 직접 등록합니다.")
	}

	switch agent.format {
	case "json":
		err := installJSON(agent, exePath)
		if err != nil {
			return err
		}
		// Claude Code JSON 폴백에서도 권한 등록
		if agent.name == "Claude Code" {
			if perr := addClaudePermission(); perr != nil {
				fmt.Fprintf(os.Stderr, "[Claude Code] 권한 자동 등록 실패 (수동 허용 필요): %v\n", perr)
			}
		}
		return nil
	case "toml":
		return installTOML(agent, exePath)
	default:
		return fmt.Errorf("지원하지 않는 설정 형식: %s", agent.format)
	}
}

// installClaudeMCPAdd는 'claude mcp add' CLI 명령으로 등록한다.
func installClaudeMCPAdd(exePath string) error {
	claudePath, err := exec.LookPath("claude")
	if err != nil {
		return err
	}

	normalizedPath := filepath.ToSlash(exePath)

	// 기존 항목 제거 후 재등록 (업데이트 지원)
	// 에러 무시 — 없으면 remove가 실패하지만 상관없음
	exec.Command(claudePath, "mcp", "remove", "agent-tool").Run()

	cmd := exec.Command(claudePath, "mcp", "add", "--scope", "user", "agent-tool", normalizedPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("claude mcp add 실패: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	// settings.json에 와일드카드 권한 자동 등록 (도구별 팝업 방지)
	if err := addClaudePermission(); err != nil {
		fmt.Fprintf(os.Stderr, "[Claude Code] 권한 자동 등록 실패 (수동 허용 필요): %v\n", err)
	} else {
		fmt.Printf("[Claude Code] 도구 권한 등록 완료 (permissions.allow: %s)\n", mcpPermissionEntry)
	}

	fmt.Printf("[Claude Code] 등록 완료 (claude mcp add)\n")
	return nil
}

const mcpPermissionEntry = "mcp__agent-tool__*"

// addClaudePermission은 ~/.claude/settings.json의 permissions.allow에
// "mcp__agent-tool__*" 와일드카드를 추가하여 모든 도구의 권한 팝업을 방지한다.
func addClaudePermission() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")

	var config map[string]any

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("settings.json 읽기 실패: %w", err)
		}
		config = make(map[string]any)
	} else {
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("settings.json 파싱 실패: %w", err)
		}
	}

	// permissions.allow 배열 가져오기
	perms, _ := config["permissions"].(map[string]any)
	if perms == nil {
		perms = make(map[string]any)
	}

	allowList, _ := perms["allow"].([]any)

	// 이미 등록되어 있는지 확인 (와일드카드 또는 개별 항목)
	for _, item := range allowList {
		if s, ok := item.(string); ok && s == mcpPermissionEntry {
			return nil // 이미 있음
		}
	}

	// 기존 개별 항목(mcp__agent-tool__xxx) 제거 후 와일드카드로 통합
	var cleaned []any
	for _, item := range allowList {
		s, ok := item.(string)
		if ok && strings.HasPrefix(s, "mcp__agent-tool__") {
			continue // 개별 항목 제거
		}
		cleaned = append(cleaned, item)
	}
	cleaned = append(cleaned, mcpPermissionEntry)

	perms["allow"] = cleaned
	config["permissions"] = perms

	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON 직렬화 실패: %w", err)
	}

	return os.WriteFile(settingsPath, output, 0644)
}

// removeClaudePermission은 settings.json에서 agent-tool 관련 권한 항목을 제거한다.
func removeClaudePermission() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return
	}

	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return
	}

	perms, _ := config["permissions"].(map[string]any)
	if perms == nil {
		return
	}

	allowList, _ := perms["allow"].([]any)
	var cleaned []any
	for _, item := range allowList {
		s, ok := item.(string)
		if ok && strings.HasPrefix(s, "mcp__agent-tool") {
			continue
		}
		cleaned = append(cleaned, item)
	}

	perms["allow"] = cleaned
	config["permissions"] = perms

	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(settingsPath, output, 0644)
}

func installJSON(agent agentConfig, exePath string) error {
	// 기존 설정 읽기 (없으면 새로 생성)
	var config map[string]any

	data, err := os.ReadFile(agent.configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("설정 파일 읽기 실패: %w", err)
		}
		config = make(map[string]any)
	} else {
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("설정 파일 파싱 실패 (JSON이 깨졌을 수 있음): %w", err)
		}
	}

	// mcpServers 키 가져오기 (없으면 생성)
	servers, ok := config[agent.jsonKey].(map[string]any)
	if !ok {
		servers = make(map[string]any)
	}

	// 이미 등록되어 있는지 확인
	if _, exists := servers["agent-tool"]; exists {
		fmt.Printf("[%s] 이미 등록되어 있습니다. 업데이트합니다.\n", agent.name)
	}

	// 경로를 슬래시로 통일 (JSON 내에서)
	normalizedPath := filepath.ToSlash(exePath)

	// agent-tool 서버 등록
	servers["agent-tool"] = map[string]any{
		"type":    "stdio",
		"command": normalizedPath,
		"args":    []string{},
		"env":     map[string]any{},
	}
	config[agent.jsonKey] = servers

	// 디렉토리가 없으면 생성
	if err := os.MkdirAll(filepath.Dir(agent.configPath), 0755); err != nil {
		return fmt.Errorf("디렉토리 생성 실패: %w", err)
	}

	// JSON 예쁘게 저장
	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON 직렬화 실패: %w", err)
	}

	if err := os.WriteFile(agent.configPath, output, 0644); err != nil {
		return fmt.Errorf("설정 파일 쓰기 실패: %w", err)
	}

	fmt.Printf("[%s] 등록 완료: %s\n", agent.name, agent.configPath)
	return nil
}

func installTOML(agent agentConfig, exePath string) error {
	normalizedPath := exePath
	if runtime.GOOS == "windows" {
		// TOML에서는 백슬래시를 이스케이프해야 하므로 슬래시 사용
		normalizedPath = filepath.ToSlash(exePath)
	}

	entry := fmt.Sprintf("\n[mcp_servers.agent-tool]\ncommand = %q\nargs = []\nenabled = true\n", normalizedPath)

	// 기존 파일 읽기
	data, err := os.ReadFile(agent.configPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("설정 파일 읽기 실패: %w", err)
	}

	content := string(data)

	// 이미 등록되어 있는지 확인
	if strings.Contains(content, "[mcp_servers.agent-tool]") {
		// 기존 항목 업데이트: 해당 섹션을 찾아서 교체
		lines := strings.Split(content, "\n")
		var result []string
		skip := false
		for _, line := range lines {
			if strings.TrimSpace(line) == "[mcp_servers.agent-tool]" {
				skip = true
				continue
			}
			// 다른 섹션이 시작되면 skip 해제.
			// 실제 섹션 헤더 판별: [로 시작하고 ]로 끝나며, =를 포함하지 않아야 함.
			// 이렇게 해야 args = ["--flag"] 같은 TOML 배열 값의 [를 섹션으로 오인하지 않는다.
			if skip {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") && !strings.Contains(trimmed, "=") {
					skip = false
				}
			}
			if !skip {
				result = append(result, line)
			}
		}
		content = strings.Join(result, "\n")
		fmt.Printf("[%s] 이미 등록되어 있습니다. 업데이트합니다.\n", agent.name)
	}

	// 끝에 추가
	content = strings.TrimRight(content, "\n") + "\n" + entry

	if err := os.MkdirAll(filepath.Dir(agent.configPath), 0755); err != nil {
		return fmt.Errorf("디렉토리 생성 실패: %w", err)
	}

	if err := os.WriteFile(agent.configPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("설정 파일 쓰기 실패: %w", err)
	}

	fmt.Printf("[%s] 등록 완료: %s\n", agent.name, agent.configPath)
	return nil
}
