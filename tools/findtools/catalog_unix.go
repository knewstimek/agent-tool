//go:build !windows

package findtools

import (
	"os"
	"path/filepath"
)

func pythonCommands() []string { return []string{"python3", "python"} }
func pipCommands() []string   { return []string{"pip3", "pip"} }

// lookupCmd is the 'which' command on Unix.
const lookupCmd = "which"

// injectKnownPaths injects Linux/macOS-specific known installation paths.
func injectKnownPaths(defs []ToolDef) {
	home := os.Getenv("HOME")

	// User local tool paths
	userBin := filepath.Join(home, "bin")          // ~/bin (manual installs)
	localBin := filepath.Join(home, ".local", "bin") // ~/.local/bin (pip, pipx, etc.)
	brewPrefix := "/opt/homebrew/bin"                // Homebrew (Apple Silicon)

	known := map[string][]string{
		"go": {
			"/usr/local/go/bin/go",
			"/usr/bin/go",
			"/snap/bin/go",
			filepath.Join(userBin, "go"),
			filepath.Join(brewPrefix, "go"),
		},
		"dotnet": {
			"/usr/share/dotnet/dotnet",
			"/usr/lib/dotnet/dotnet",
			filepath.Join(home, ".dotnet", "dotnet"),
			"/snap/bin/dotnet",
		},
		"node": {
			"/usr/local/bin/node",
			"/usr/bin/node",
			"/snap/bin/node",
			filepath.Join(home, ".nvm", "versions", "node", "*", "bin", "node"), // glob
			filepath.Join(home, ".fnm", "node-versions", "*", "installation", "bin", "node"), // fnm
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
			"/usr/lib/jvm/java-*/bin/java",                                           // glob — Debian/Ubuntu
			"/usr/lib/jvm/jre-*/bin/java",                                             // glob — RHEL/Fedora
			filepath.Join(home, ".sdkman", "candidates", "java", "current", "bin", "java"), // SDKMAN
		},
		"javac": {
			"/usr/bin/javac",
			"/usr/lib/jvm/java-*/bin/javac",
			"/usr/lib/jvm/jre-*/bin/javac",
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
			"/snap/bin/cmake",
			filepath.Join(brewPrefix, "cmake"),
		},
		"make": {
			"/usr/bin/make",
			"/usr/bin/gmake",
			filepath.Join(brewPrefix, "make"),
		},
		"ninja": {
			"/usr/bin/ninja",
			"/usr/local/bin/ninja",
			"/usr/bin/ninja-build", // RHEL/Fedora package name
			filepath.Join(brewPrefix, "ninja"),
		},
		"git": {
			"/usr/bin/git",
			"/usr/local/bin/git",
		},
		"gh": {
			"/usr/bin/gh",
			"/usr/local/bin/gh",
			"/snap/bin/gh",
			filepath.Join(localBin, "gh"),
			filepath.Join(userBin, "gh"),
			filepath.Join(brewPrefix, "gh"),
		},
		"docker": {
			"/usr/bin/docker",
			"/usr/local/bin/docker",
			"/snap/bin/docker",
			filepath.Join(brewPrefix, "docker"),
		},
		"bun": {
			filepath.Join(home, ".bun", "bin", "bun"),
			"/usr/local/bin/bun",
			filepath.Join(userBin, "bun"),
			filepath.Join(brewPrefix, "bun"),
		},
		"deno": {
			filepath.Join(home, ".deno", "bin", "deno"),
			"/usr/local/bin/deno",
			filepath.Join(userBin, "deno"),
			filepath.Join(brewPrefix, "deno"),
		},
	}

	for i := range defs {
		if paths, ok := known[defs[i].Name]; ok {
			// Filter out empty prefix paths (prevent relative paths when HOME is empty)
			var valid []string
			for _, p := range paths {
				if !filepath.IsAbs(p) {
					continue
				}
				valid = append(valid, p)
			}
			defs[i].KnownPaths = valid
		}
	}
}
