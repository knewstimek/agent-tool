//go:build windows

package findtools

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
)

// discoverMSVC searches for cl.exe (MSVC compiler).
// 1. vswhere.exe → VS install path → cl.exe
// 2. Direct glob fallback
func discoverMSVC() ToolInfo {
	info := ToolInfo{Name: "cl (MSVC)"}

	// 1. Try vswhere.exe
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
				// Glob for cl.exe path
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

	// 2. Direct glob fallback
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

// getMSVCVersion extracts the MSVC version from the cl.exe path.
// Example path: .../MSVC/14.38.33130/bin/... → "14.38.33130"
func getMSVCVersion(clPath string) string {
	// The directory name after "MSVC" in the path is the version
	parts := strings.Split(filepath.ToSlash(clPath), "/")
	for i, p := range parts {
		if p == "MSVC" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// discoverPyLauncher searches for Windows Python Launcher (py.exe).
func discoverPyLauncher() ToolInfo {
	info := ToolInfo{Name: "py (launcher)"}

	path := lookupPath("py")
	if path == "" {
		// Known locations
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

	// Get installed version list with py -0p
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, path, "-0p").CombinedOutput()
	if err == nil {
		// Use the first line as the default version
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 0 {
			info.Version = strings.TrimSpace(lines[0])
		}
	}

	return info
}
