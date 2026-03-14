package bash

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	maxOutputSize  = 64 * 1024 // 64 KB
	maxTimeoutSec  = 600
	sentinelPrefix = "___SENTINEL_"
	sentinelSuffix = "___"
)

// execResult holds the result of a command execution.
type execResult struct {
	Output   string
	ExitCode int
}

// readResult holds a single line read from stdout.
type readResult struct {
	line string
	err  error
}

// executeCommand runs a command on an existing shell session using sentinel markers.
func executeCommand(ctx context.Context, sess *shellSession, command string, timeoutSec int) (*execResult, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if !sess.alive() {
		return nil, fmt.Errorf("shell session is dead")
	}

	// Update lastUsed at start to prevent reaper from killing during long commands
	sess.lastUsed = time.Now()

	// Generate unique sentinel
	b := make([]byte, 8)
	rand.Read(b)
	id := hex.EncodeToString(b)
	sentinel := sentinelPrefix + id + "_EC_"

	// Build the command with sentinel
	fullCmd := buildSentinelCommand(command, sentinel)

	// Write command to stdin
	_, err := fmt.Fprintln(sess.stdin, fullCmd)
	if err != nil {
		return nil, fmt.Errorf("write to stdin: %w", err)
	}

	// Read stdout until sentinel line using goroutine to avoid blocking
	var output strings.Builder
	outputSize := 0
	deadline := time.After(time.Duration(timeoutSec) * time.Second)
	exitCode := 0

	lineCh := make(chan readResult, 1)

	// Background reader goroutine
	readNext := func() {
		line, err := sess.stdoutR.ReadString('\n')
		lineCh <- readResult{line, err}
	}
	go readNext()

	for {
		select {
		case <-ctx.Done():
			// Context cancelled — kill the session so the blocked reader goroutine exits
			sess.close()
			return nil, ctx.Err()
		case <-deadline:
			// Timeout — kill the session so the blocked reader goroutine exits
			sess.close()
			return nil, fmt.Errorf("command timed out after %d seconds", timeoutSec)
		case r := <-lineCh:
			if r.err != nil {
				return nil, fmt.Errorf("read stdout: %w", r.err)
			}

			trimmed := strings.TrimRight(r.line, "\r\n")

			// Check for sentinel
			if strings.HasPrefix(trimmed, sentinel) {
				ecStr := strings.TrimPrefix(trimmed, sentinel)
				ecStr = strings.TrimSuffix(ecStr, sentinelSuffix)
				fmt.Sscanf(ecStr, "%d", &exitCode)
				goto done
			}

			// Accumulate output (with size limit)
			if outputSize < maxOutputSize {
				remaining := maxOutputSize - outputSize
				if len(r.line) > remaining {
					output.WriteString(r.line[:remaining])
				} else {
					output.WriteString(r.line)
				}
				outputSize += len(r.line)
			}

			// Start next read
			go readNext()
		}
	}

done:
	sess.lastUsed = time.Now()

	raw := output.String()
	raw = strings.TrimRight(raw, "\r\n")

	return &execResult{
		Output:   decodeOutput(raw),
		ExitCode: exitCode,
	}, nil
}

// buildSentinelCommand wraps a command with sentinel markers.
// Platform-specific implementations in shell_*.go would be cleaner,
// but the logic is simple enough to handle with runtime.GOOS.
func buildSentinelCommand(command string, sentinel string) string {
	return buildSentinelCmd(command, sentinel)
}
