//go:build windows

package ssh

import (
	"fmt"
	"net"

	gossh "golang.org/x/crypto/ssh"
)

// getAgentAuth returns an error on Windows.
// Windows SSH agent requires named pipe access (go-winio dependency) which is
// not included to minimize dependencies. Use key_file or password authentication instead.
func getAgentAuth() (gossh.AuthMethod, net.Conn, error) {
	return nil, nil, fmt.Errorf("SSH agent is not supported on Windows; use key_file or password authentication")
}
