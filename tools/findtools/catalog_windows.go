//go:build windows

package findtools

import (
	"os"
	"path/filepath"
)

func pythonCommands() []string { return []string{"python", "py"} }
func pipCommands() []string   { return []string{"pip", "pip3"} }

// lookupCmd는 Windows에서 where 명령이다.
const lookupCmd = "where"

// injectKnownPaths는 Windows 전용 알려진 설치 경로를 주입한다.
func injectKnownPaths(defs []ToolDef) {
	home := os.Getenv("USERPROFILE")
	pf := os.Getenv("ProgramFiles")
	pfx86 := os.Getenv("ProgramFiles(x86)")
	appdata := os.Getenv("APPDATA")
	localAppdata := os.Getenv("LOCALAPPDATA")

	known := map[string][]string{
		"go": {
			filepath.Join(pf, "Go", "bin", "go.exe"),
			`C:\Go\bin\go.exe`,
		},
		"dotnet": {
			filepath.Join(pf, "dotnet", "dotnet.exe"),
		},
		"node": {
			filepath.Join(pf, "nodejs", "node.exe"),
			filepath.Join(appdata, "nvm", "*", "node.exe"), // nvm-windows
		},
		"npm": {
			filepath.Join(pf, "nodejs", "npm.cmd"),
		},
		"npx": {
			filepath.Join(pf, "nodejs", "npx.cmd"),
		},
		"python3": {
			filepath.Join(pf, "Python312", "python.exe"),
			filepath.Join(pf, "Python311", "python.exe"),
			filepath.Join(pf, "Python310", "python.exe"),
			filepath.Join(pf, "Python39", "python.exe"),
			filepath.Join(localAppdata, "Programs", "Python", "Python312", "python.exe"),
			filepath.Join(localAppdata, "Programs", "Python", "Python311", "python.exe"),
			filepath.Join(localAppdata, "Programs", "Python", "Python310", "python.exe"),
		},
		"pip": {
			filepath.Join(pf, "Python312", "Scripts", "pip.exe"),
			filepath.Join(pf, "Python311", "Scripts", "pip.exe"),
			filepath.Join(pf, "Python310", "Scripts", "pip.exe"),
		},
		"java": {
			filepath.Join(pf, "Java", "jdk*", "bin", "java.exe"),          // glob
			filepath.Join(pf, "Eclipse Adoptium", "jdk-*", "bin", "java.exe"), // Adoptium
		},
		"javac": {
			filepath.Join(pf, "Java", "jdk*", "bin", "javac.exe"),
			filepath.Join(pf, "Eclipse Adoptium", "jdk-*", "bin", "javac.exe"),
		},
		"cargo": {
			filepath.Join(home, ".cargo", "bin", "cargo.exe"),
		},
		"rustc": {
			filepath.Join(home, ".cargo", "bin", "rustc.exe"),
		},
		"rustup": {
			filepath.Join(home, ".cargo", "bin", "rustup.exe"),
		},
		"gcc": {
			`C:\msys64\mingw64\bin\gcc.exe`,
			`C:\msys64\ucrt64\bin\gcc.exe`,
			`C:\MinGW\bin\gcc.exe`,
			filepath.Join(pf, "mingw-w64", "bin", "gcc.exe"),
		},
		"g++": {
			`C:\msys64\mingw64\bin\g++.exe`,
			`C:\msys64\ucrt64\bin\g++.exe`,
			`C:\MinGW\bin\g++.exe`,
		},
		"clang": {
			filepath.Join(pf, "LLVM", "bin", "clang.exe"),
		},
		"clang++": {
			filepath.Join(pf, "LLVM", "bin", "clang++.exe"),
		},
		"cmake": {
			filepath.Join(pf, "CMake", "bin", "cmake.exe"),
		},
		"make": {
			`C:\msys64\usr\bin\make.exe`,
			filepath.Join(pfx86, "GnuWin32", "bin", "make.exe"),
		},
		"ninja": {
			filepath.Join(pf, "Ninja", "ninja.exe"),
		},
		"git": {
			filepath.Join(pf, "Git", "cmd", "git.exe"),
			filepath.Join(pf, "Git", "bin", "git.exe"),
		},
		"gh": {
			filepath.Join(pf, "GitHub CLI", "gh.exe"),
			filepath.Join(localAppdata, "GitHub CLI", "gh.exe"),
		},
		"docker": {
			filepath.Join(pf, "Docker", "Docker", "resources", "bin", "docker.exe"),
		},
		"bun": {
			filepath.Join(home, ".bun", "bin", "bun.exe"),
		},
		"deno": {
			filepath.Join(home, ".deno", "bin", "deno.exe"),
		},
	}

	for i := range defs {
		if paths, ok := known[defs[i].Name]; ok {
			defs[i].KnownPaths = paths
		}
	}
}

// vswhereExe는 vswhere.exe의 표준 위치를 반환한다.
func vswhereExe() string {
	pfx86 := os.Getenv("ProgramFiles(x86)")
	return filepath.Join(pfx86, "Microsoft Visual Studio", "Installer", "vswhere.exe")
}

// vsBasePaths는 Visual Studio 표준 설치 경로 후보이다 (glob용).
func vsBasePaths() []string {
	pf := os.Getenv("ProgramFiles")
	pfx86 := os.Getenv("ProgramFiles(x86)")
	return []string{
		filepath.Join(pf, "Microsoft Visual Studio"),
		filepath.Join(pfx86, "Microsoft Visual Studio"),
	}
}
