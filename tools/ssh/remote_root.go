package ssh

import (
	"fmt"
	"path"
	"strings"
)

func windowsRemotePath(p string) bool {
	return len(p) >= 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && (p[2] == '/' || p[2] == '\\')
}

func cleanRemotePath(p string) string {
	if windowsRemotePath(p) {
		p = strings.ReplaceAll(p, "\\", "/")
		return p[:2] + path.Clean(p[2:])
	}
	return path.Clean(p)
}

// normalizeRemoteRoot is host-independent: never apply local filepath rules to
// a remote path. Shell selection describes the server's SSH command interpreter.
func normalizeRemoteRoot(input *SSHInput) error {
	if input.RemoteRoot == "" {
		if input.RemoteShell != "" {
			return fmt.Errorf("remote_shell requires remote_root")
		}
		return nil
	}
	root := input.RemoteRoot
	if strings.ContainsAny(root, "\x00\r\n") || (!strings.HasPrefix(root, "/") && !windowsRemotePath(root)) {
		return fmt.Errorf("remote_root must be an absolute POSIX or drive-based Windows path")
	}
	if windowsRemotePath(root) {
		root = strings.ReplaceAll(root, "\\", "/")
	}
	input.RemoteRoot = cleanRemotePath(root)
	if input.RemoteShell == "" {
		input.RemoteShell = "posix"
		if windowsRemotePath(root) {
			input.RemoteShell = "cmd"
		}
	}
	switch input.RemoteShell {
	case "posix", "powershell":
	case "cmd":
		// cmd expands percent and delayed-expansion tokens even inside quotes.
		if strings.ContainsAny(root, "\"%!^&|<>") {
			return fmt.Errorf("remote_root contains characters unsupported by cmd; use remote_shell=powershell with a PowerShell SSH default shell")
		}
	default:
		return fmt.Errorf("remote_shell must be posix, cmd, or powershell")
	}
	return nil
}

// ResolveRemotePath anchors relative SFTP paths without changing explicit
// absolute paths. remote_root is a working directory, not a security sandbox.
func ResolveRemotePath(root, p string) string {
	if root == "" || p == "" {
		return p
	}
	if windowsRemotePath(root) {
		p = strings.ReplaceAll(p, "\\", "/")
	}
	if strings.HasPrefix(p, "/") || windowsRemotePath(p) {
		return cleanRemotePath(p)
	}
	if windowsRemotePath(root) {
		return root[:2] + path.Join(root[2:], p)
	}
	return path.Join(root, p)
}

// DisplayRemotePath only shortens descendants, respecting component boundaries.
func DisplayRemotePath(root, p string) string {
	if root == "" || p == "" {
		return p
	}
	root = cleanRemotePath(root)
	clean := p
	if windowsRemotePath(root) {
		clean = strings.ReplaceAll(clean, "\\", "/")
	}
	clean = cleanRemotePath(clean)
	comparison, base := clean, root
	if windowsRemotePath(root) {
		comparison, base = strings.ToLower(clean), strings.ToLower(root)
	}
	if comparison == base {
		return "."
	}
	prefix := strings.TrimRight(base, "/") + "/"
	if strings.HasPrefix(comparison, prefix) {
		return clean[len(prefix):]
	}
	return p
}

func quotePOSIX(s string) string      { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func quotePowerShell(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// applyRemoteRoot changes execution cwd, never command operands or output.
// A failed directory change must prevent the command from running.
func applyRemoteRoot(input *SSHInput) {
	if input.RemoteRoot == "" {
		return
	}
	ps := "Set-Location -LiteralPath " + quotePowerShell(input.RemoteRoot) + " -ErrorAction Stop;\n"
	if input.PowerShellScript != "" {
		input.PowerShellScript = ps + input.PowerShellScript
		return
	}
	switch input.RemoteShell {
	case "powershell":
		input.Command = ps + input.Command
	case "cmd":
		input.Command = "cd /d \"" + strings.ReplaceAll(input.RemoteRoot, "/", "\\") + "\" && (" + input.Command + ")"
	default:
		input.Command = "cd " + quotePOSIX(input.RemoteRoot) + " && {\n" + input.Command + "\n}"
	}
}
