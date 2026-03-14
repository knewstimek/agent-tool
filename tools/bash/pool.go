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

type shellSession struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdoutR   *bufio.Reader
	key       string
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
			entry.lastUsed = time.Now()
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

	// Start shell WITHOUT holding the lock
	sess, err := startShellSession(key, cwd)
	if err != nil {
		return nil, false, err
	}

	// Re-acquire lock and double-check
	p.mu.Lock()
	defer p.mu.Unlock()

	if entry, ok := p.sessions[key]; ok {
		// Another goroutine won the race
		sess.close()
		entry.lastUsed = time.Now()
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

// evictOldestLocked removes the least recently used session.
// Must be called with p.mu held.
func (p *shellPool) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range p.sessions {
		if oldestKey == "" || entry.lastUsed.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.lastUsed
		}
	}

	if oldestKey != "" {
		if entry, ok := p.sessions[oldestKey]; ok {
			entry.close()
		}
		delete(p.sessions, oldestKey)
	}
}
