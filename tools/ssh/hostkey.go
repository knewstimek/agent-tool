package ssh

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// knownHostsMu serializes writes to known_hosts to prevent concurrent
// TOFU callbacks from corrupting the file.
var knownHostsMu sync.Mutex

// buildHostKeyCallback returns a host key callback based on the verification mode.
//   - "strict": requires known_hosts entry (default)
//   - "tofu": trust on first use — auto-adds new hosts, rejects changed keys
//   - "none": insecure, skip verification
func buildHostKeyCallback(mode string) (gossh.HostKeyCallback, error) {
	switch mode {
	case "none":
		return gossh.InsecureIgnoreHostKey(), nil

	case "tofu":
		return tofuCallback()

	default: // "strict"
		khPath, err := defaultKnownHostsPath()
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(khPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("known_hosts file not found at %s. Use host_key_check=tofu for first connection", khPath)
		}
		return knownhosts.New(khPath)
	}
}

// tofuCallback implements Trust On First Use.
// - If the host is already known, verifies the key matches.
// - If the host key has changed, returns an error (MITM protection).
// - If the host is new, auto-adds to known_hosts.
func tofuCallback() (gossh.HostKeyCallback, error) {
	khPath, err := defaultKnownHostsPath()
	if err != nil {
		return nil, err
	}

	// If known_hosts exists, check against it first
	if _, err := os.Stat(khPath); err == nil {
		existingCb, err := knownhosts.New(khPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse known_hosts %s: %w", khPath, err)
		}
		return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
			err := existingCb(hostname, remote, key)
			if err == nil {
				return nil // Host already known and key matches
			}
			// Key changed → possible MITM, always reject
			if isKeyChanged(err) {
				return fmt.Errorf("HOST KEY CHANGED for %s — possible man-in-the-middle attack. Remove the old key from %s to proceed", hostname, khPath)
			}
			// New host → auto-add (serialized to prevent corruption)
			return appendKnownHost(khPath, hostname, key)
		}, nil
	}

	// No known_hosts file → create on first use
	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		return appendKnownHost(khPath, hostname, key)
	}, nil
}

// isKeyChanged checks if the error indicates a host key change.
func isKeyChanged(err error) bool {
	keyErr, ok := err.(*knownhosts.KeyError)
	if !ok {
		return false
	}
	// If Want is non-empty, the host was known but key changed
	return len(keyErr.Want) > 0
}

// defaultKnownHostsPath returns ~/.ssh/known_hosts.
func defaultKnownHostsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory for known_hosts: %w", err)
	}
	return filepath.Join(home, ".ssh", "known_hosts"), nil
}

// appendKnownHost adds a host key entry to the known_hosts file.
// Uses a mutex to serialize concurrent writes from TOFU callbacks.
func appendKnownHost(path string, hostname string, key gossh.PublicKey) error {
	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts: %w", err)
	}
	defer f.Close()

	line := knownhosts.Line([]string{hostname}, key)
	_, err = fmt.Fprintln(f, line)
	return err
}
