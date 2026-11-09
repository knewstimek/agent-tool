package ssh

import (
	"encoding/base64"
	"fmt"
	"path"
	"strings"
	"unicode/utf16"
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

const defaultPowerShellPrefix = "powershell.exe -NoProfile -NonInteractive -EncodedCommand "

func decodedPowerShellText(s string) string {
	return "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString([]byte(s)) + "'))"
}

// User text is compiled separately, preserving using/param declarations. Never
// insert command text into the syntax controlling whether cwd setup succeeded.
func powerShellInvocation(textExpression, root string) string {
	location := ""
	if root != "" {
		location = "Set-Location -LiteralPath " + quotePowerShell(root) + " -ErrorAction Stop; "
	}
	return location + ". ([scriptblock]::Create(" + textExpression + " + \"`n`nif (`$?) { exit 0 } else { exit 1 }\"))"
}

func cmdProcessScript(root, command string) string {
	// WorkingDirectory is a process attribute, so cmd expands %CD% only after
	// launch. The command remains data until the child cmd parses it once.
	return "$ErrorActionPreference='Stop';$i=New-Object Diagnostics.ProcessStartInfo;" +
		"$i.FileName=$env:ComSpec;$i.UseShellExecute=$false;$i.WorkingDirectory=" + quotePowerShell(root) + ";" +
		"$i.Arguments='/d /s /c \"' + (" + decodedPowerShellText(command) + ") + '\"';" +
		"$p=[Diagnostics.Process]::Start($i);$p.WaitForExit();exit $p.ExitCode"
}

// prepareSSHExecution chooses staging after including all generated syntax.
// POSIX command data uses a separate sh parser; Windows uses PowerShell's data
// APIs or a separately compiled scriptblock, never a command grouping wrapper.
func prepareSSHExecution(input SSHInput) (string, *powerShellPlan, error) {
	plan, err := planPowerShell(input)
	if err != nil {
		return "", nil, err
	}
	if input.RemoteRoot == "" {
		return input.Command, plan, nil
	}
	if plan != nil {
		plan.remoteRoot = input.RemoteRoot
		return "", plan, nil
	}
	if input.Command == "" {
		return "", nil, nil
	}
	if input.RemoteShell == "posix" {
		return "cd " + quotePOSIX(input.RemoteRoot) + " && exec sh -c " + quotePOSIX(input.Command), nil, nil
	}
	plan = &powerShellPlan{script: input.Command, prefix: defaultPowerShellPrefix, executable: "powershell.exe", remoteRoot: input.RemoteRoot}
	script := psPrelude + "try { " + powerShellInvocation(decodedPowerShellText(input.Command), input.RemoteRoot) + " } catch { [Console]::Error.WriteLine($_); exit 1 }"
	if input.RemoteShell == "cmd" {
		plan.script = cmdProcessScript(input.RemoteRoot, input.Command)
		plan.remoteRoot = ""
		script = psPrelude + plan.script
	}
	// The PowerShell default shell parses a data-only launcher directly; cmd
	// needs an explicit PowerShell executable to host the process API.
	command := script
	if input.RemoteShell == "cmd" {
		command = defaultPowerShellPrefix + encodePowerShell(script)
	}
	if len(utf16.Encode([]rune(command))) >= powerShellInlineLimit {
		return "", plan, nil
	}
	return command, nil, nil
}
