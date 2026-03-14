//go:build windows

package bash

import (
	"bufio"
	"fmt"
	"os/exec"
	"time"

	"agent-tool/common"
)


// shellCommand returns the shell binary for Windows.
func shellCommand() (string, []string) {
	return "cmd.exe", []string{"/Q"} // /Q disables echo
}

// startShellSession starts a new interactive shell process.
func startShellSession(key string, cwd string) (*shellSession, error) {
	shell, args := shellCommand()
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
		createdAt: now,
		lastUsed:  now,
	}, nil
}

// decodeOutput converts Windows console output to UTF-8.
func decodeOutput(raw string) string {
	return common.DecodeConsoleOutput([]byte(raw))
}

// buildSentinelCmd wraps a command with exit code capture and sentinel marker.
func buildSentinelCmd(command string, sentinel string) string {
	return fmt.Sprintf("%s & echo. & echo %s%%ERRORLEVEL%%%%%s", command, sentinel, "___")
}
