package ssh

import (
	"fmt"
	"net"
	"os"

	gossh "golang.org/x/crypto/ssh"
)

// authResult holds authentication methods and any agent connection that must
// be closed when the SSH session ends.
type authResult struct {
	methods   []gossh.AuthMethod
	agentConn net.Conn // nil if SSH agent not used
}

// buildAuthMethods builds SSH authentication methods from input parameters.
// Priority: key_file → password → SSH agent (fallback).
// The caller must close authResult.agentConn (if non-nil) when the session ends.
func buildAuthMethods(input SSHInput) (*authResult, error) {
	result := &authResult{}

	// 1. Key file
	if input.KeyFile != "" {
		keyBytes, err := os.ReadFile(input.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", input.KeyFile, err)
		}
		signer, err := parseKey(keyBytes, input.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		result.methods = append(result.methods, gossh.PublicKeys(signer))
	}

	// 2. Password
	if input.Password != "" {
		result.methods = append(result.methods, gossh.Password(input.Password))
	}

	// 3. SSH Agent (explicit request or fallback when no other auth)
	if input.UseAgent || len(result.methods) == 0 {
		agentAuth, agentConn, err := getAgentAuth()
		if err == nil && agentAuth != nil {
			result.methods = append(result.methods, agentAuth)
			result.agentConn = agentConn
		}
	}

	if len(result.methods) == 0 {
		return nil, fmt.Errorf("no authentication method available: provide key_file, password, or ensure SSH agent is running")
	}

	return result, nil
}

// parseKey parses a PEM-encoded private key, optionally with passphrase.
func parseKey(keyBytes []byte, passphrase string) (gossh.Signer, error) {
	if passphrase != "" {
		return gossh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
	}
	return gossh.ParsePrivateKey(keyBytes)
}
