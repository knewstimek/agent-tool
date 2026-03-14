//go:build !windows

package findtools

import (
	"os"
	"path/filepath"
)

func pythonCommands() []string { return []string{"python3", "python"} }
func pipCommands() []string   { return []string{"pip3", "pip"} }

// lookupCmd는 Unix에서 which 명령이다.
const lookupCmd = "which"

// injectKnownPaths는 Linux/macOS 전용 알려진 설치 경로를 주입한다.
func injectKnownPaths(defs []ToolDef) {
	home := os.Getenv("HOME")

	known := map[string][]string{
		"go": {
			"/usr/local/go/bin/go",
			"/usr/bin/go",
			"/snap/bin/go",
		},
		"dotnet": {
			"/usr/share/dotnet/dotnet",
			"/usr/lib/dotnet/dotnet",
			filepath.Join(home, ".dotnet", "dotnet"),
		},
		"node": {
			"/usr/local/bin/node",
			"/usr/bin/node",
			filepath.Join(home, ".nvm", "versions", "node", "*", "bin", "node"), // glob
		},
		"npm": {
			"/usr/local/bin/npm",
			"/usr/bin/npm",
		},
		"npx": {
			"/usr/local/bin/npx",
			"/usr/bin/npx",
		},
		"python3": {
			"/usr/bin/python3",
			"/usr/local/bin/python3",
			filepath.Join(home, ".pyenv", "shims", "python3"),
		},
		"pip": {
			"/usr/bin/pip3",
			"/usr/local/bin/pip3",
			filepath.Join(home, ".pyenv", "shims", "pip3"),
		},
		"java": {
			"/usr/bin/java",
			"/usr/lib/jvm/java-*/bin/java", // glob
		},
		"javac": {
			"/usr/bin/javac",
			"/usr/lib/jvm/java-*/bin/javac",
		},
		"cargo": {
			filepath.Join(home, ".cargo", "bin", "cargo"),
			"/usr/bin/cargo",
		},
		"rustc": {
			filepath.Join(home, ".cargo", "bin", "rustc"),
			"/usr/bin/rustc",
		},
		"rustup": {
			filepath.Join(home, ".cargo", "bin", "rustup"),
		},
		"gcc": {
			"/usr/bin/gcc",
			"/usr/local/bin/gcc",
		},
		"g++": {
			"/usr/bin/g++",
			"/usr/local/bin/g++",
		},
		"clang": {
			"/usr/bin/clang",
			"/usr/local/bin/clang",
		},
		"clang++": {
			"/usr/bin/clang++",
			"/usr/local/bin/clang++",
		},
		"cmake": {
			"/usr/bin/cmake",
			"/usr/local/bin/cmake",
		},
		"make": {
			"/usr/bin/make",
			"/usr/bin/gmake",
		},
		"ninja": {
			"/usr/bin/ninja",
			"/usr/local/bin/ninja",
		},
		"git": {
			"/usr/bin/git",
			"/usr/local/bin/git",
		},
		"docker": {
			"/usr/bin/docker",
			"/usr/local/bin/docker",
		},
		"bun": {
			filepath.Join(home, ".bun", "bin", "bun"),
			"/usr/local/bin/bun",
		},
		"deno": {
			filepath.Join(home, ".deno", "bin", "deno"),
			"/usr/local/bin/deno",
		},
	}

	for i := range defs {
		if paths, ok := known[defs[i].Name]; ok {
			defs[i].KnownPaths = paths
		}
	}
}
