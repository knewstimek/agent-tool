//go:build windows

package findtools

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
)

// discoverMSVC는 cl.exe (MSVC 컴파일러)를 탐색한다.
// 1. vswhere.exe → VS 설치 경로 → cl.exe
// 2. 직접 glob 폴백
func discoverMSVC() ToolInfo {
	info := ToolInfo{Name: "cl (MSVC)"}

	// 1. vswhere.exe 시도
	vswhere := vswhereExe()
	if fileExists(vswhere) {
		ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
		defer cancel()

		out, err := exec.CommandContext(ctx, vswhere,
			"-latest",
			"-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
			"-property", "installationPath",
		).Output()
		if err == nil {
			vsPath := strings.TrimSpace(string(out))
			if vsPath != "" {
				// cl.exe 경로 glob
				pattern := filepath.Join(vsPath, "VC", "Tools", "MSVC", "*", "bin", "Hostx64", "x64", "cl.exe")
				matches, _ := filepath.Glob(pattern)
				if len(matches) > 0 {
					clPath := matches[len(matches)-1]
					info.Path = clPath
					info.Source = "special"
					info.Version = getMSVCVersion(clPath)
					return info
				}
			}
		}
	}

	// 2. 직접 glob 폴백
	for _, base := range vsBasePaths() {
		// {2022,2019,2017}\{Community,Professional,Enterprise}\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe
		for _, year := range []string{"2022", "2019", "2017"} {
			for _, edition := range []string{"Community", "Professional", "Enterprise", "BuildTools"} {
				pattern := filepath.Join(base, year, edition, "VC", "Tools", "MSVC", "*", "bin", "Hostx64", "x64", "cl.exe")
				matches, _ := filepath.Glob(pattern)
				if len(matches) > 0 {
					clPath := matches[len(matches)-1]
					info.Path = clPath
					info.Source = "known_path"
					info.Version = getMSVCVersion(clPath)
					return info
				}
			}
		}
	}

	return info
}

// getMSVCVersion은 cl.exe 경로에서 MSVC 버전을 추출한다.
// 경로 예: .../MSVC/14.38.33130/bin/... → "14.38.33130"
func getMSVCVersion(clPath string) string {
	// 경로에서 MSVC 다음 디렉토리명이 버전
	parts := strings.Split(filepath.ToSlash(clPath), "/")
	for i, p := range parts {
		if p == "MSVC" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// discoverPyLauncher는 Windows Python Launcher(py.exe)를 탐색한다.
func discoverPyLauncher() ToolInfo {
	info := ToolInfo{Name: "py (launcher)"}

	path := lookupPath("py")
	if path == "" {
		// 알려진 위치
		candidates := []string{
			`C:\Windows\py.exe`,
			filepath.Join(`C:\Program Files`, "Python Launcher", "py.exe"),
		}
		for _, c := range candidates {
			if fileExists(c) {
				path = c
				break
			}
		}
	}

	if path == "" {
		return info
	}

	info.Path = path
	info.Source = "path"

	// py -0p로 설치된 버전 목록 가져오기
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, path, "-0p").CombinedOutput()
	if err == nil {
		// 첫 줄을 기본 버전으로 사용
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 0 {
			info.Version = strings.TrimSpace(lines[0])
		}
	}

	return info
}
