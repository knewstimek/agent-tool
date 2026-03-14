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

// DiscoverAll discovers all tools from the catalog in parallel.
// If category is empty or "all", discovers everything.
func DiscoverAll(category string) []ToolInfo {
	catalog := Catalog()

	// Filter discovery targets
	var targets []ToolDef
	for _, def := range catalog {
		if category != "" && category != "all" && def.Category != category {
			continue
		}
		targets = append(targets, def)
	}

	// Parallel discovery
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

	// Special tools (parallel)
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

// discoverTool discovers a single tool.
func discoverTool(def ToolDef) ToolInfo {
	info := ToolInfo{Name: def.Name}

	// 1. Environment variable lookup
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
		// Windows: auto-append .exe
		candidate = withExeSuffix(candidate)
		if fileExists(candidate) {
			info.Path = candidate
			info.Source = "env"
			info.Version = getVersion(candidate, def.VersionArg)
			return info
		}
	}

	// 2. where/which lookup
	for _, cmd := range def.Commands {
		if path := lookupPath(cmd); path != "" {
			info.Path = path
			info.Source = "path"
			info.Version = getVersion(path, def.VersionArg)
			return info
		}
	}

	// 3. Known path lookup
	for _, p := range def.KnownPaths {
		p = withExeSuffix(p)
		// Support glob patterns (containing *)
		if strings.Contains(p, "*") {
			matches, err := filepath.Glob(p)
			if err == nil && len(matches) > 0 {
				// Use the latest (last) entry
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

// lookupPath finds a command using where (Windows) or which (Linux).
func lookupPath(cmd string) string {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, lookupCmd, cmd).Output()
	if err != nil {
		return ""
	}

	// where may return multiple lines -> use the first line
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return ""
	}
	path := strings.TrimSpace(lines[0])

	// Windows 'where' may return Microsoft Store app links -> filter them out
	if runtime.GOOS == "windows" {
		for _, line := range lines {
			p := strings.TrimSpace(line)
			if p == "" || strings.Contains(p, "WindowsApps") {
				continue
			}
			if fileExists(p) {
				return p
			}
		}
		// If no non-WindowsApps path found, fall through to return the first valid path
	}

	if path != "" && fileExists(path) {
		return path
	}
	return ""
}

// getVersion returns the version string of a tool.
func getVersion(path, versionArg string) string {
	if versionArg == "" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, versionArg)
	// java -version outputs to stderr. Limit output to 4KB (defense against malicious binaries).
	// stdout/stderr must share the same limitWriter for accurate limit enforcement.
	var buf bytes.Buffer
	lw := &limitWriter{w: &buf, limit: 4096}
	cmd.Stdout = lw
	cmd.Stderr = lw
	err := cmd.Run()
	if err != nil {
		return ""
	}

	raw := strings.TrimSpace(buf.String())
	if raw == "" {
		return ""
	}

	// Take only the first line and clean up
	firstLine := strings.Split(raw, "\n")[0]
	firstLine = strings.TrimSpace(firstLine)

	return cleanVersion(firstLine)
}

// cleanVersion removes unnecessary parts from version output.
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
	// "gcc (Ubuntu 13.2.0-4ubuntu3) 13.2.0" -> last version number
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

	// Otherwise: return as-is (truncate to 80 chars max)
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// fileExists checks if a file exists at the path (excluding directories).
func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// withExeSuffix appends .exe suffix on Windows if not already present.
func withExeSuffix(path string) string {
	if runtime.GOOS != "windows" {
		return path
	}
	// If already has an extension (.exe, .cmd, .bat), keep as-is
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".exe" || ext == ".cmd" || ext == ".bat" {
		return path
	}
	// Do not modify glob patterns
	if strings.Contains(path, "*") {
		return path
	}
	return path + ".exe"
}

// limitWriter is an io.Writer that writes at most 'limit' bytes.
type limitWriter struct {
	w       io.Writer
	limit   int
	written int
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	remaining := lw.limit - lw.written
	if remaining <= 0 {
		return len(p), nil // discard excess (not an error)
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := lw.w.Write(p)
	lw.written += n
	return n, err
}
