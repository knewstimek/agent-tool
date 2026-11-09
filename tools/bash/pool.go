package bash

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultIdleTimeout = 30 * time.Minute
	maxSessions        = 5
	reaperInterval     = 60 * time.Second
)

// shellKind identifies the type of shell used for a session.
type shellKind int

const (
	kindDefault    shellKind = 0 // bash/sh on Unix
	kindPowerShell shellKind = 1 // Windows PowerShell 5.1 — does NOT support && / ||
	kindGitBash    shellKind = 2
	kindCmd        shellKind = 3
	kindPwsh       shellKind = 4 // PowerShell 7+ (pwsh.exe) — supports && / || natively
)

func (k shellKind) String() string {
	switch k {
	case kindPowerShell:
		return "powershell"
	case kindPwsh:
		return "pwsh"
	case kindGitBash:
		return "git-bash"
	case kindCmd:
		return "cmd"
	default:
		return "bash"
	}
}

type shellSession struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdoutR   *bufio.Reader
	key       string
	shellKind shellKind
	createdAt time.Time
	lastUsed  time.Time
	mu        sync.Mutex // prevents concurrent command execution on same session
	closeOnce sync.Once  // prevents double close
}

func (s *shellSession) close() {
	s.closeOnce.Do(func() {
		_ = s.stdin.Close()
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
			_ = s.cmd.Wait()
		}
	})
}

// alive checks if the shell process is still running.
func (s *shellSession) alive() bool {
	if s.cmd.Process == nil {
		return false
	}
	// Process.Signal(0) returns nil if process exists (Unix).
	// On Windows this always returns an error, so we check ProcessState instead.
	if s.cmd.ProcessState != nil {
		return false // already exited
	}
	return true
}

type shellPoolKey struct {
	owner *mcp.ServerSession
	name  string
}

type shellPool struct {
	mu       sync.Mutex
	sessions map[shellPoolKey]*shellSession
}

var pool = &shellPool{
	sessions: make(map[shellPoolKey]*shellSession),
}

func init() {
	go pool.reaper()
}

// getOrCreate returns an existing shell session or creates a new one.
func (p *shellPool) getOrCreate(key shellPoolKey, cwd string) (*shellSession, bool, error) {
	p.mu.Lock()

	// Check existing session
	if entry, ok := p.sessions[key]; ok {
		if !entry.mu.TryLock() {
			p.mu.Unlock()
			return entry, false, nil
		}
		if entry.alive() {
			// lastUsed is updated by executeCommand under entry.mu; skip here to avoid data race
			entry.mu.Unlock()
			p.mu.Unlock()
			return entry, false, nil
		}
		// Dead session, clean up
		entry.close()
		entry.mu.Unlock()
		delete(p.sessions, key)
	}

	p.mu.Unlock()

	// Start shell WITHOUT holding the lock — startShellSession blocks during
	// process spawn, and holding the lock would prevent other goroutines
	// (including the reaper) from accessing the pool for the duration.
	sess, err := startShellSession(key.name, cwd)
	if err != nil {
		return nil, false, err
	}

	// Re-acquire lock and double-check
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check: another goroutine may have created the same session
	// while we were spawning ours. Use theirs and discard ours.
	if entry, ok := p.sessions[key]; ok {
		sess.close()
		return entry, false, nil
	}

	if len(p.sessions) >= maxSessions {
		if !p.evictOldestLocked(key.owner) {
			sess.close()
			return nil, false, fmt.Errorf("shell capacity reached; close an idle session or wait for an active command")
		}
	}

	p.sessions[key] = sess
	return sess, true, nil
}

// remove closes and removes a session by key.
func (p *shellPool) remove(key shellPoolKey, expected *shellSession) bool {
	p.mu.Lock()
	entry, ok := p.sessions[key]
	if !ok || expected != nil && entry != expected {
		p.mu.Unlock()
		return false
	}
	delete(p.sessions, key)
	p.mu.Unlock()

	// Lock entry AFTER releasing pool lock to prevent deadlock
	entry.mu.Lock()
	entry.close()
	entry.mu.Unlock()
	return true
}

// reaper periodically removes idle sessions.
func (p *shellPool) reaper() {
	ticker := time.NewTicker(reaperInterval)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for key, entry := range p.sessions {
			if !entry.mu.TryLock() {
				continue
			}
			if now.Sub(entry.lastUsed) > defaultIdleTimeout || !entry.alive() {
				entry.close()
				delete(p.sessions, key)
			}
			entry.mu.Unlock()
		}
		p.mu.Unlock()
	}
}

// evictOldestLocked removes only this owner's least recently used idle session.
// Must be called with p.mu held. Skips sessions with active commands.
func (p *shellPool) evictOldestLocked(owner *mcp.ServerSession) bool {
	var oldestKey shellPoolKey
	var oldest *shellSession
	for key, entry := range p.sessions {
		if key.owner != owner || !entry.mu.TryLock() {
			continue
		}
		if oldest == nil || entry.lastUsed.Before(oldest.lastUsed) {
			if oldest != nil {
				oldest.mu.Unlock()
			}
			oldestKey, oldest = key, entry
		} else {
			entry.mu.Unlock()
		}
	}
	if oldest == nil {
		return false
	}
	oldest.close()
	oldest.mu.Unlock()
	delete(p.sessions, oldestKey)
	return true
}
