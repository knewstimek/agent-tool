package ssh

import (
	"bytes"
	"context"
	"io"

	gossh "golang.org/x/crypto/ssh"
)

const maxOutputSize = 1024 * 1024 // 1MB per stream

// execResult holds the result of a remote command execution.
type execResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// executeCommand runs a command on the remote server with timeout.
func executeCommand(ctx context.Context, client *gossh.Client, command string) (*execResult, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &limitWriter{w: &stdoutBuf, limit: maxOutputSize}
	session.Stderr = &limitWriter{w: &stderrBuf, limit: maxOutputSize}

	// Run command in goroutine for timeout support
	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	select {
	case <-ctx.Done():
		// Timeout — kill remote process and close session to unblock
		// the goroutine running session.Run (prevents goroutine leak).
		_ = session.Signal(gossh.SIGKILL)
		session.Close()
		<-done // wait for goroutine to exit
		return nil, ctx.Err()
	case err := <-done:
		result := &execResult{
			Stdout:   stdoutBuf.String(),
			Stderr:   stderrBuf.String(),
			ExitCode: 0,
		}
		if err != nil {
			if exitErr, ok := err.(*gossh.ExitError); ok {
				result.ExitCode = exitErr.ExitStatus()
			} else {
				return nil, err
			}
		}
		return result, nil
	}
}

// limitWriter writes at most `limit` bytes. Excess bytes are silently discarded.
type limitWriter struct {
	w       io.Writer
	limit   int
	written int
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	remaining := lw.limit - lw.written
	if remaining <= 0 {
		return len(p), nil // discard, report all consumed
	}
	if len(p) > remaining {
		// Write only what fits, but report all bytes as consumed
		// to satisfy io.Writer contract (callers expect len(p) on success).
		n, err := lw.w.Write(p[:remaining])
		lw.written += n
		if err != nil {
			return n, err
		}
		return len(p), nil
	}
	n, err := lw.w.Write(p)
	lw.written += n
	return n, err
}
