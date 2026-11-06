package bash

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"agent-tool/common"
)

const (
	maxOutputSize  = common.DefaultOutputChars
	maxTimeoutSec  = 600
	sentinelPrefix = "___SENTINEL_"
	sentinelSuffix = "___"
)

var errSessionBusy = errors.New("session busy")

// execResult holds the result of a command execution.
type execResult struct {
	Output        string
	ExitCode      int
	OriginalBytes int64
	Truncated     bool
}

// readResult holds a single line read from stdout.
type readResult struct {
	line string
	err  error
}

// executeCommand runs a command on an existing shell session using sentinel markers.
func executeCommand(ctx context.Context, sess *shellSession, command string, timeoutSec int) (*execResult, error) {
	// Fail fast instead of queueing: since bash calls can yield a job_id, the
	// previous command may legitimately still be running, and queueing behind
	// it would block the agent for exactly as long as yielding was meant to avoid.
	if !sess.mu.TryLock() {
		return nil, errSessionBusy
	}
	defer sess.mu.Unlock()

	if !sess.alive() {
		return nil, fmt.Errorf("shell session is dead")
	}

	// Update lastUsed at start to prevent reaper from killing during long commands
	sess.lastUsed = time.Now()

	// Generate a random sentinel so command output cannot accidentally match it.
	// 8 bytes = 64-bit entropy, making collisions practically impossible.
	b := make([]byte, 8)
	rand.Read(b)
	id := hex.EncodeToString(b)
	sentinel := sentinelPrefix + id + "_EC_"

	// Build the command with sentinel
	fullCmd := buildSentinelCmd(sess.shellKind, command, sentinel)

	// Write command to stdin
	_, err := fmt.Fprintln(sess.stdin, fullCmd)
	if err != nil {
		return nil, fmt.Errorf("write to stdin: %w", err)
	}

	// Read stdout until sentinel line using goroutine to avoid blocking
	output := common.NewBoundedCapture(maxOutputSize)
	deadline := time.After(time.Duration(timeoutSec) * time.Second)
	exitCode := 0

	// Buffer of 1 lets the reader goroutine send its result without blocking
	// even if the select loop is processing the previous line.
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

			// Skip echoed command lines (PowerShell echoes input including sentinel markers)
			if strings.Contains(trimmed, sentinel) {
				go readNext()
				continue
			}

			_, _ = output.Write([]byte(r.line))

			// Start next read
			go readNext()
		}
	}

done:
	sess.lastUsed = time.Now()

	raw, originalBytes, truncated := output.Result()
	raw = strings.TrimRight(raw, "\r\n")

	return &execResult{
		Output:        decodeOutput(sess.shellKind, raw),
		ExitCode:      exitCode,
		OriginalBytes: originalBytes,
		Truncated:     truncated,
	}, nil
}
