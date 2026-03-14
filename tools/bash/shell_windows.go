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
	// PowerShell Core (pwsh.exe) — cross-platform, newer
	if path, err := exec.LookPath("pwsh.exe"); err == nil {
		return path, psArgs(), kindPowerShell
	}

	// Windows PowerShell (available on Windows 7+)
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

// containsCmdOperators checks if a command uses && or || operators
// that are not supported in Windows PowerShell 5.1 (added in PS 7).
func containsCmdOperators(cmd string) bool {
	return strings.Contains(cmd, "&&") || strings.Contains(cmd, "||")
}

// buildSentinelCmd wraps a command with exit code capture and sentinel marker.
func buildSentinelCmd(kind shellKind, command string, sentinel string) string {
	switch kind {
	case kindPowerShell:
		userCmd := command
		// Windows PowerShell 5.1 doesn't support && and || operators.
		// Route through cmd.exe when these operators are present.
		if containsCmdOperators(command) {
			escaped := strings.ReplaceAll(command, "'", "''")
			userCmd = fmt.Sprintf("& cmd /c '%s'", escaped)
		}
		// $LASTEXITCODE: set by native commands. $?: set by all commands.
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
