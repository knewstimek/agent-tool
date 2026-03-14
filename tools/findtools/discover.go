package findtools

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const execTimeout = 3 * time.Second

// DiscoverAll은 카탈로그의 모든 도구를 병렬로 탐색한다.
// category가 비어있거나 "all"이면 전체 탐색.
func DiscoverAll(category string) []ToolInfo {
	catalog := Catalog()

	// 탐색 대상 필터링
	var targets []ToolDef
	for _, def := range catalog {
		if category != "" && category != "all" && def.Category != category {
			continue
		}
		targets = append(targets, def)
	}

	// 병렬 탐색
	results := make([]ToolInfo, len(targets))
	var wg sync.WaitGroup
	for i, def := range targets {
		wg.Add(1)
		go func(idx int, d ToolDef) {
			defer wg.Done()
			results[idx] = discoverTool(d)
		}(i, def)
	}
	wg.Wait()

	// 특수 도구 (병렬)
	var clInfo, pyInfo ToolInfo
	var wg2 sync.WaitGroup
	if category == "" || category == "all" || category == "c_cpp" {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			clInfo = discoverMSVC()
		}()
	}
	if category == "" || category == "all" || category == "python" {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			pyInfo = discoverPyLauncher()
		}()
	}
	wg2.Wait()

	if clInfo.Path != "" {
		results = append(results, clInfo)
	}
	if pyInfo.Path != "" {
		results = append(results, pyInfo)
	}

	return results
}

// discoverTool은 단일 도구를 탐색한다.
func discoverTool(def ToolDef) ToolInfo {
	info := ToolInfo{Name: def.Name}

	// 1. 환경변수 탐색
	for _, env := range def.EnvVars {
		val := os.Getenv(env)
		if val == "" {
			continue
		}
		var candidate string
		if def.EnvSubPath != "" {
			candidate = filepath.Join(val, def.EnvSubPath)
		} else {
			candidate = val
		}
		// Windows: .exe 자동 추가
		candidate = withExeSuffix(candidate)
		if fileExists(candidate) {
			info.Path = candidate
			info.Source = "env"
			info.Version = getVersion(candidate, def.VersionArg)
			return info
		}
	}

	// 2. where/which 탐색
	for _, cmd := range def.Commands {
		if path := lookupPath(cmd); path != "" {
			info.Path = path
			info.Source = "path"
			info.Version = getVersion(path, def.VersionArg)
			return info
		}
	}

	// 3. 알려진 경로 탐색
	for _, p := range def.KnownPaths {
		p = withExeSuffix(p)
		// glob 패턴 지원 (* 포함)
		if strings.Contains(p, "*") {
			matches, err := filepath.Glob(p)
			if err == nil && len(matches) > 0 {
				// 가장 최신 (마지막) 항목 사용
				candidate := matches[len(matches)-1]
				if fileExists(candidate) {
					info.Path = candidate
					info.Source = "known_path"
					info.Version = getVersion(candidate, def.VersionArg)
					return info
				}
			}
			continue
		}
		if fileExists(p) {
			info.Path = p
			info.Source = "known_path"
			info.Version = getVersion(p, def.VersionArg)
			return info
		}
	}

	return info // not found
}

// lookupPath는 where(Windows) 또는 which(Linux)로 명령을 찾는다.
func lookupPath(cmd string) string {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, lookupCmd, cmd).Output()
	if err != nil {
		return ""
	}

	// where는 여러 줄 반환 가능 → 첫 줄만 사용
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return ""
	}
	path := strings.TrimSpace(lines[0])

	// Windows의 where는 Microsoft Store 앱 링크를 반환할 수 있음 → 필터
	if strings.Contains(path, "WindowsApps") && runtime.GOOS == "windows" {
		// WindowsApps의 python.exe는 스토어 리다이렉터일 수 있음
		// 실제 실행 가능한지 확인
		if len(lines) > 1 {
			path = strings.TrimSpace(lines[1])
		}
	}

	if path != "" && fileExists(path) {
		return path
	}
	return ""
}

// getVersion은 도구의 버전 문자열을 반환한다.
func getVersion(path, versionArg string) string {
	if versionArg == "" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, versionArg)
	// java -version은 stderr에 출력. 출력 크기를 4KB로 제한 (악성 바이너리 방어).
	var buf bytes.Buffer
	cmd.Stdout = &limitWriter{w: &buf, limit: 4096}
	cmd.Stderr = &limitWriter{w: &buf, limit: 4096}
	err := cmd.Run()
	if err != nil {
		return ""
	}

	raw := strings.TrimSpace(buf.String())
	if raw == "" {
		return ""
	}

	// 첫 줄만 취하고 정리
	firstLine := strings.Split(raw, "\n")[0]
	firstLine = strings.TrimSpace(firstLine)

	return cleanVersion(firstLine)
}

// cleanVersion은 버전 출력에서 불필요한 부분을 제거한다.
func cleanVersion(s string) string {
	// "go version go1.22.1 windows/amd64" → "go1.22.1"
	if strings.HasPrefix(s, "go version ") {
		parts := strings.Fields(s)
		if len(parts) >= 3 {
			return parts[2]
		}
	}
	// "git version 2.43.0.windows.1" → "2.43.0.windows.1"
	if strings.HasPrefix(s, "git version ") {
		return strings.TrimPrefix(s, "git version ")
	}
	// "gh version 2.69.0 (2025-03-19)" → "2.69.0"
	if strings.HasPrefix(s, "gh version ") {
		parts := strings.Fields(s)
		if len(parts) >= 3 {
			return parts[2]
		}
	}
	// "Docker version 24.0.7, build afdd53b" → "24.0.7"
	if strings.HasPrefix(s, "Docker version ") {
		v := strings.TrimPrefix(s, "Docker version ")
		if idx := strings.Index(v, ","); idx > 0 {
			return v[:idx]
		}
		return v
	}
	// "GNU Make 4.4.1" → "4.4.1"
	if strings.HasPrefix(s, "GNU Make ") {
		return strings.TrimPrefix(s, "GNU Make ")
	}
	// "cmake version 3.28.1" → "3.28.1"
	if strings.HasPrefix(s, "cmake version ") {
		return strings.TrimPrefix(s, "cmake version ")
	}
	// "cargo 1.75.0 (..." → "1.75.0"
	if strings.HasPrefix(s, "cargo ") {
		parts := strings.Fields(s)
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	// "rustc 1.75.0 (..." → "1.75.0"
	if strings.HasPrefix(s, "rustc ") {
		parts := strings.Fields(s)
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	// "rustup 1.26.0 (..." → "1.26.0"
	if strings.HasPrefix(s, "rustup ") {
		parts := strings.Fields(s)
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	// "pip 23.3.2 from ..." → "23.3.2"
	if strings.HasPrefix(s, "pip ") {
		parts := strings.Fields(s)
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	// "gcc (Ubuntu 13.2.0-4ubuntu3) 13.2.0" → 마지막 버전 번호
	if strings.Contains(s, "gcc") || strings.Contains(s, "g++") {
		parts := strings.Fields(s)
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
	}
	// "clang version 17.0.6" → "17.0.6"
	if strings.Contains(s, "clang version ") {
		idx := strings.Index(s, "clang version ")
		rest := s[idx+len("clang version "):]
		parts := strings.Fields(rest)
		if len(parts) > 0 {
			return parts[0]
		}
	}
	// "openjdk version \"21.0.1\"" → "21.0.1"
	if strings.Contains(s, "version \"") {
		start := strings.Index(s, "version \"") + len("version \"")
		end := strings.Index(s[start:], "\"")
		if end > 0 {
			return s[start : start+end]
		}
	}
	// "ninja 1.11.1" → "1.11.1"
	if strings.HasPrefix(s, "ninja") {
		parts := strings.Fields(s)
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	// "Microsoft (R) Build Engine version 17.8.3+195e7f5a3 ..." → "17.8.3"
	if strings.Contains(s, "Build Engine version ") {
		idx := strings.Index(s, "Build Engine version ") + len("Build Engine version ")
		rest := s[idx:]
		// "17.8.3+xxx" → "17.8.3"
		parts := strings.FieldsFunc(rest, func(r rune) bool {
			return r == '+' || r == ' '
		})
		if len(parts) > 0 {
			return parts[0]
		}
	}

	// 그 외: 그대로 반환 (최대 80자 truncate)
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// fileExists는 경로에 파일이 존재하는지 확인한다 (디렉토리 제외).
func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// withExeSuffix는 Windows에서 .exe 확장자가 없으면 추가한다.
func withExeSuffix(path string) string {
	if runtime.GOOS != "windows" {
		return path
	}
	// 이미 확장자가 있으면 (.exe, .cmd, .bat) 그대로
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".exe" || ext == ".cmd" || ext == ".bat" {
		return path
	}
	// glob 패턴은 건드리지 않음
	if strings.Contains(path, "*") {
		return path
	}
	return path + ".exe"
}

// limitWriter는 최대 limit 바이트까지만 쓰는 io.Writer이다.
type limitWriter struct {
	w       io.Writer
	limit   int
	written int
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	remaining := lw.limit - lw.written
	if remaining <= 0 {
		return len(p), nil // 초과분은 버림 (에러 아님)
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := lw.w.Write(p)
	lw.written += n
	return n, err
}
