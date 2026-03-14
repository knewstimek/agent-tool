//go:build windows

package bash

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"agent-tool/common"
)

// detectShell finds the best available shell: PowerShell > git bash > cmd.exe.
// PowerShell is preferred because it provides native UTF-8 output, structured
// exit codes via $LASTEXITCODE, and better PATH handling than cmd.exe.
func detectShell() (string, []string, shellKind) {
	// PowerShell 7+ (pwsh.exe) — supports && / || natively
	if path, err := exec.LookPath("pwsh.exe"); err == nil {
		return path, psArgs(), kindPwsh
	}

	// Windows PowerShell 5.1 — does NOT support && / ||
	if path, err := exec.LookPath("powershell.exe"); err == nil {
		return path, psArgs(), kindPowerShell
	}

	// Git bash — check known install locations only (avoid WSL bash)
	gitPaths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Git", "bin", "bash.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "Git", "bin", "bash.exe"),
	}
	for _, p := range gitPaths {
		if _, err := os.Stat(p); err == nil {
			return p, []string{}, kindGitBash
		}
	}

	// Fallback: cmd.exe
	return "cmd.exe", []string{"/Q"}, kindCmd
}

// psArgs returns PowerShell arguments with an init script that sets
// UTF-8 encoding and enhances PATH with common tool directories.
func psArgs() []string {
	var init strings.Builder
	init.WriteString("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ")
	init.WriteString("$OutputEncoding = [System.Text.Encoding]::UTF8; ")
	init.WriteString("function prompt {''}; ") // suppress prompt to reduce echo noise
	init.WriteString(`$__p = @("$env:USERPROFILE\bin","$env:USERPROFILE\scoop\shims","$env:USERPROFILE\.cargo\bin","C:\ProgramData\chocolatey\bin"); `)
	init.WriteString(`foreach($d in $__p){if(Test-Path $d){$env:PATH += ";$d"}}`)

	return []string{"-NoProfile", "-NoLogo", "-NoExit", "-Command", init.String()}
}

// startShellSession starts a new interactive shell process.
func startShellSession(key string, cwd string) (*shellSession, error) {
	shell, args, kind := detectShell()
	cmd := exec.Command(shell, args...)

	if cwd != "" {
		cmd.Dir = cwd
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	// Merge stderr into stdout for simplicity
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		stdin.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}

	now := time.Now()
	return &shellSession{
		cmd:       cmd,
		stdin:     stdin,
		stdoutR:   bufio.NewReaderSize(stdout, 64*1024),
		key:       key,
		shellKind: kind,
		createdAt: now,
		lastUsed:  now,
	}, nil
}

// decodeOutput converts shell output to UTF-8.
// PowerShell and git bash output UTF-8 directly; cmd.exe needs console decoding.
func decodeOutput(kind shellKind, raw string) string {
	if kind == kindCmd {
		return common.DecodeConsoleOutput([]byte(raw))
	}
	return raw
}

// findGitBash returns the path to git bash if installed, empty string otherwise.
func findGitBash() string {
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Git", "bin", "bash.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "Git", "bin", "bash.exe"),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// buildPSChainOps converts parsed chain segments to PowerShell equivalents.
//
//	"cmd1 && cmd2"  →  "$global:LASTEXITCODE=0; cmd1; if($global:LASTEXITCODE -eq 0){ cmd2 }"
//	"cmd1 || cmd2"  →  "$global:LASTEXITCODE=0; cmd1; if($global:LASTEXITCODE -ne 0){ cmd2 }"
func buildPSChainOps(parsed chainParse) string {
	var result strings.Builder
	// Initialize $LASTEXITCODE to 0 so the first "if" check works even when
	// the first command is a PS cmdlet (which doesn't set $LASTEXITCODE).
	result.WriteString("$global:LASTEXITCODE=0; ")
	result.WriteString(parsed.Segments[0].Text)

	for i := 0; i < len(parsed.Segments)-1; i++ {
		op := parsed.Segments[i].Op
		next := parsed.Segments[i+1].Text
		if op == "&&" {
			result.WriteString("; if($global:LASTEXITCODE -eq 0){ ")
		} else {
			result.WriteString("; if($global:LASTEXITCODE -ne 0){ ")
		}
		result.WriteString(next)
		result.WriteString(" }")
	}

	return result.String()
}

// delegateToGitBash wraps a command for execution via git-bash from PowerShell.
// Uses PS double-quotes so bash receives original single-quotes intact.
func delegateToGitBash(command, gbPath string) string {
	escaped := strings.ReplaceAll(command, "`", "``")
	escaped = strings.ReplaceAll(escaped, "$", "`$")
	escaped = strings.ReplaceAll(escaped, `"`, "`\"")
	return fmt.Sprintf("& '%s' -c \"%s\"", gbPath, escaped)
}

// delegateToCmdExe wraps a command for execution via cmd.exe from PowerShell.
func delegateToCmdExe(command string) string {
	escaped := strings.ReplaceAll(command, "'", "''")
	return fmt.Sprintf("& cmd /c '%s'", escaped)
}

// delegateToExternalShell wraps a command for execution via git-bash or cmd.exe.
// Prefer git-bash (handles Unix paths, UTF-8), fall back to cmd.exe.
func delegateToExternalShell(command string) string {
	if gb := findGitBash(); gb != "" {
		return delegateToGitBash(command, gb)
	}
	return delegateToCmdExe(command)
}

// buildSentinelCmd wraps a command with exit code capture and sentinel marker.
func buildSentinelCmd(kind shellKind, command string, sentinel string) string {
	switch kind {
	case kindPwsh:
		// PowerShell 7+ supports && and || natively — pass through as-is.
		return fmt.Sprintf(
			"%s; $__ec = $LASTEXITCODE; if ($null -eq $__ec) { $__ec = if ($?) {0} else {1} }; Write-Host \"\"; Write-Host \"%s$__ec%s\"",
			command, sentinel, sentinelSuffix,
		)
	case kindPowerShell:
		// PowerShell 5.1: && / || cause a parse error that kills the entire line
		// including the sentinel, causing the reader to hang forever.
		// Parse once, then choose strategy based on result.
		// handler.go also emits a warning so the agent learns to use ; instead.
		userCmd := command
		parsed := parseChainOps(command)
		if parsed.NeedsDelegation() {
			// Command contains && / || inside $() or () — PS 5.1 can't parse
			// these even as subexpressions. Delegate the whole command.
			userCmd = delegateToExternalShell(command)
		} else if parsed.HasChainOps() {
			if parsed.HasEmptySegment() {
				// Syntax errors like "&& cmd" — still can't pass raw to PS 5.1.
				userCmd = delegateToExternalShell(command)
			} else {
				// Simple top-level chain: transform to PS equivalents.
				userCmd = buildPSChainOps(parsed)
			}
		}
		return fmt.Sprintf(
			"%s; $__ec = $LASTEXITCODE; if ($null -eq $__ec) { $__ec = if ($?) {0} else {1} }; Write-Host \"\"; Write-Host \"%s$__ec%s\"",
			userCmd, sentinel, sentinelSuffix,
		)
	case kindGitBash:
		// Same pattern as Unix bash
		return fmt.Sprintf(
			"%s; EXIT_CODE=$?; echo \"\"; echo \"%s${EXIT_CODE}%s\"",
			command, sentinel, sentinelSuffix,
		)
	default: // kindCmd
		// Capture exit code in a temp var to avoid %sentinelSuffix being parsed as env var
		return fmt.Sprintf(
			"%s & set __ec=%%ERRORLEVEL%% & echo. & echo %s%%__ec%%%s",
			command, sentinel, sentinelSuffix,
		)
	}
}
