package bash

import (
	"bufio"
	"io"
	"os/exec"
	"sync"
	"time"
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
	kindPowerShell shellKind = 1
	kindGitBash    shellKind = 2
	kindCmd        shellKind = 3
)

func (k shellKind) String() string {
	switch k {
	case kindPowerShell:
		return "powershell"
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
	mu        sync.Mutex    // prevents concurrent command execution on same session
	closeOnce sync.Once     // prevents double close
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

type shellPool struct {
	mu       sync.Mutex
	sessions map[string]*shellSession
}

var pool = &shellPool{
	sessions: make(map[string]*shellSession),
}

func init() {
	go pool.reaper()
}

// getOrCreate returns an existing shell session or creates a new one.
func (p *shellPool) getOrCreate(key string, cwd string) (*shellSession, bool, error) {
	p.mu.Lock()

	// Check existing session
	if entry, ok := p.sessions[key]; ok {
		if entry.alive() {
			// lastUsed is updated by executeCommand under entry.mu; skip here to avoid data race
			p.mu.Unlock()
			return entry, false, nil
		}
		// Dead session, clean up
		entry.close()
		delete(p.sessions, key)
	}

	// Evict oldest if at capacity
	if len(p.sessions) >= maxSessions {
		p.evictOldestLocked()
	}

	p.mu.Unlock()

	// Start shell WITHOUT holding the lock — startShellSession blocks during
	// process spawn, and holding the lock would prevent other goroutines
	// (including the reaper) from accessing the pool for the duration.
	sess, err := startShellSession(key, cwd)
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
		p.evictOldestLocked()
	}

	p.sessions[key] = sess
	return sess, true, nil
}

// remove closes and removes a session by key.
func (p *shellPool) remove(key string) bool {
	p.mu.Lock()
	entry, ok := p.sessions[key]
	if !ok {
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
			if now.Sub(entry.lastUsed) > defaultIdleTimeout || !entry.alive() {
				// TryLock: skip if a command is running on this session
				if entry.mu.TryLock() {
					entry.close()
					delete(p.sessions, key)
					entry.mu.Unlock()
				}
			}
		}
		p.mu.Unlock()
	}
}

// evictOldestLocked removes the least recently used idle session.
// Must be called with p.mu held. Skips sessions with active commands.
func (p *shellPool) evictOldestLocked() {
	// Collect candidates sorted by lastUsed (oldest first)
	type candidate struct {
		key   string
		entry *shellSession
	}
	var candidates []candidate
	for key, entry := range p.sessions {
		candidates = append(candidates, candidate{key, entry})
	}
	// Sort: oldest lastUsed first
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].entry.lastUsed.Before(candidates[i].entry.lastUsed) {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	for _, c := range candidates {
		if c.entry.mu.TryLock() {
			c.entry.close()
			c.entry.mu.Unlock()
			delete(p.sessions, c.key)
			return
		}
		// Session is busy, try next oldest
	}
}
