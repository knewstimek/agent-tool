//go:build !windows

package ssh

import (
	"fmt"
	"net"
	"os"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// getAgentAuth returns an SSH agent authentication method and the underlying
// connection. The caller must close agentConn when the SSH session ends.
func getAgentAuth() (gossh.AuthMethod, net.Conn, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to SSH agent: %w", err)
	}

	agentClient := agent.NewClient(conn)
	return gossh.PublicKeysCallback(agentClient.Signers), conn, nil
}
