package ssh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	gossh "golang.org/x/crypto/ssh"
)

const (
	// Leave room below cmd.exe's 8191 UTF-16 code unit limit.
	powerShellInlineLimit    = 8000
	maxPowerShellScriptBytes = 4 << 20
)

type powerShellPlan struct {
	script     string
	prefix     string
	executable string
}

func planPowerShell(input SSHInput) (*powerShellPlan, error) {
	if input.PowerShellScript != "" {
		if input.Command != "" {
			return nil, fmt.Errorf("use either command or powershell_script, not both")
		}
		if len(input.PowerShellScript) > maxPowerShellScriptBytes || !utf8.ValidString(input.PowerShellScript) {
			return nil, fmt.Errorf("powershell_script must be valid UTF-8 and at most 4 MiB")
		}
		return &powerShellPlan{input.PowerShellScript, "powershell.exe -NoProfile -NonInteractive -EncodedCommand ", "powershell.exe"}, nil
	}
	if len(utf16.Encode([]rune(input.Command))) < powerShellInlineLimit {
		return nil, nil
	}
	tokens := strings.Fields(input.Command)
	if len(tokens) == 0 {
		return nil, nil
	}
	executable := strings.ToLower(tokens[0])
	switch executable {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
	default:
		return nil, nil // Arbitrary shell commands must never be rewritten.
	}
	unsupported := fmt.Errorf("long PowerShell command cannot be safely staged; pass the script text in powershell_script without shell wrappers or redirection")
	for i := 1; i < len(tokens); i++ {
		switch strings.ToLower(tokens[i]) {
		case "-encodedcommand", "-enc", "-ec", "-e":
			if i+2 != len(tokens) {
				return nil, unsupported
			}
			data, err := base64.StdEncoding.DecodeString(strings.Trim(tokens[i+1], "\"'"))
			if err != nil || len(data)%2 != 0 || len(data) > 2*maxPowerShellScriptBytes {
				return nil, fmt.Errorf("EncodedCommand must contain valid UTF-16LE Base64; alternatively use powershell_script")
			}
			units := make([]uint16, len(data)/2)
			for n := range units {
				units[n] = uint16(data[2*n]) | uint16(data[2*n+1])<<8
			}
			// Reject malformed surrogate pairs instead of changing script contents.
			for n := 0; n < len(units); n++ {
				if units[n] >= 0xd800 && units[n] <= 0xdbff {
					if n+1 == len(units) || units[n+1] < 0xdc00 || units[n+1] > 0xdfff {
						return nil, fmt.Errorf("EncodedCommand contains invalid UTF-16")
					}
					n++
				} else if units[n] >= 0xdc00 && units[n] <= 0xdfff {
					return nil, fmt.Errorf("EncodedCommand contains invalid UTF-16")
				}
			}
			script := string(utf16.Decode(units))
			if len(script) > maxPowerShellScriptBytes {
				return nil, fmt.Errorf("PowerShell script exceeds 4 MiB")
			}
			return &powerShellPlan{script, strings.Join(tokens[:i], " ") + " -EncodedCommand ", tokens[0]}, nil
		case "-noprofile", "-nop", "-noninteractive", "-noni", "-nologo", "-sta", "-mta":
		case "-executionpolicy", "-ep":
			i++
			if i >= len(tokens) || !oneOfFold(tokens[i], "Bypass", "Unrestricted", "RemoteSigned", "AllSigned", "Restricted", "Default", "Undefined") {
				return nil, unsupported
			}
		default:
			return nil, unsupported
		}
	}
	return nil, unsupported
}

func oneOfFold(value string, choices ...string) bool {
	for _, choice := range choices {
		if strings.EqualFold(value, choice) {
			return true
		}
	}
	return false
}

func encodePowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	data := make([]byte, len(units)*2)
	for i, unit := range units {
		data[2*i], data[2*i+1] = byte(unit), byte(unit>>8)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func powerShellBootstrap(remotePath string) string {
	literal := "'" + strings.ReplaceAll(remotePath, "'", "''") + "'"
	// Execute script text in the EncodedCommand scope, preserving exit and error
	// behavior without subjecting the uploaded file to execution-policy checks.
	// finally runs on normal completion, script errors, and explicit exit.
	// PowerShell 5 resets $? after a parenthesized expression. Capture the last
	// command's status inside the script block rather than after invoking it.
	return "try { . ([scriptblock]::Create([IO.File]::ReadAllText(" + literal + ",[Text.Encoding]::UTF8) + \"`n`nif (`$?) { exit 0 } else { exit 1 }\")) } finally { try { Remove-Item -LiteralPath " + literal + " -Force -ErrorAction Stop } catch { [Console]::Error.WriteLine('[agent-tool cleanup] temporary script deletion failed') } }"
}

type stagedPowerShell struct {
	command    string
	remotePath string
	executable string
}

func stagePowerShell(ctx context.Context, client *gossh.Client, plan *powerShellPlan) (*stagedPowerShell, error) {
	probe := plan.executable + " -NoProfile -NonInteractive -EncodedCommand " + encodePowerShell("[Console]::Out.Write([IO.Path]::GetTempPath())")
	result, err := executeCommand(ctx, client, probe, 8192, "head")
	if err != nil {
		return nil, fmt.Errorf("cannot locate remote PowerShell temporary directory: %w", err)
	}
	dir := strings.TrimSpace(result.Stdout)
	if result.ExitCode != 0 || result.StdoutTruncated || len(dir) < 3 || dir[1] != ':' ||
		!((dir[0] >= 'A' && dir[0] <= 'Z') || (dir[0] >= 'a' && dir[0] <= 'z')) ||
		(dir[2] != '\\' && dir[2] != '/') || strings.ContainsAny(dir, "\x00\r\n") {
		return nil, fmt.Errorf("powershell_script requires a Windows target with an absolute, drive-based temporary directory")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	remotePath := strings.TrimRight(strings.ReplaceAll(dir, "\\", "/"), "/") + "/agent-tool-" + hex.EncodeToString(random) + ".ps1"
	command := plan.prefix + encodePowerShell(powerShellBootstrap(remotePath))
	if len(utf16.Encode([]rune(command))) >= powerShellInlineLimit {
		return nil, fmt.Errorf("temporary script launcher exceeds the Windows command-line limit")
	}
	content := []byte("\ufeff" + plan.script)
	upload := plan.executable + " -NoProfile -NonInteractive -EncodedCommand " + encodePowerShell(powerShellUpload(remotePath, len(content)))
	if len(utf16.Encode([]rune(upload))) >= powerShellInlineLimit {
		return nil, fmt.Errorf("temporary script uploader exceeds the Windows command-line limit")
	}
	// Script bytes travel on the SSH channel's stdin, never in the command
	// line. This also works with legacy Windows SSH servers without SFTP.
	result, err = executeCommandWithInput(ctx, client, upload, 4096, "head_tail", strings.NewReader(base64.StdEncoding.EncodeToString(content)))
	if err != nil {
		// An upload without a confirmed exit may still be finishing remotely.
		// Do not delete a path whose exclusive creation was not confirmed.
		return nil, fmt.Errorf("PowerShell script staging failed: %w; upload completion was not confirmed and a remote temporary file may remain", err)
	}
	if err == nil && result.ExitCode != 0 {
		err = fmt.Errorf("remote temporary script upload failed (exit code %d)", result.ExitCode)
	}
	if err != nil {
		warning := ""
		if strings.Contains(result.Stderr, "[agent-tool cleanup]") {
			warning = "temporary script upload cleanup failed; a remote temporary file may remain"
		}
		return nil, fmt.Errorf("PowerShell script staging failed: %w%s", err, warningSuffix(warning))
	}
	return &stagedPowerShell{command, remotePath, plan.executable}, nil
}

func powerShellUpload(remotePath string, size int) string {
	literal := "'" + strings.ReplaceAll(remotePath, "'", "''") + "'"
	// Decode and validate the complete input before exclusive create. A broken
	// upload must not execute or leave a successfully staged partial script.
	return fmt.Sprintf("$f=$null; $ok=$false; try { $b=[Convert]::FromBase64String([Console]::In.ReadToEnd()); if ($b.Length -ne %d) { throw 'incomplete script upload' }; $f=[IO.File]::Open(%s,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); $f.Write($b,0,$b.Length); $ok=$true } catch { [Console]::Error.WriteLine('temporary script upload failed'); exit 1 } finally { if ($f) { $f.Dispose(); if (!$ok) { try { [IO.File]::Delete(%s) } catch { [Console]::Error.WriteLine('[agent-tool cleanup] temporary script deletion failed') } } } }", size, literal, literal)
}

func cleanupStagedPowerShell(client *gossh.Client, remotePath, executable string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	literal := "'" + strings.ReplaceAll(remotePath, "'", "''") + "'"
	script := "try { if (Test-Path -LiteralPath " + literal + ") { Remove-Item -LiteralPath " + literal + " -Force -ErrorAction Stop } } catch { exit 1 }"
	result, err := executeCommand(ctx, client, executable+" -NoProfile -NonInteractive -EncodedCommand "+encodePowerShell(script), 1024, "head")
	if err != nil || result.ExitCode != 0 {
		return "temporary PowerShell script cleanup failed; a remote temporary file may remain"
	}
	return ""
}

func warningSuffix(warning string) string {
	if warning == "" {
		return ""
	}
	return "; " + warning
}

func finishStagedPowerShell(client *gossh.Client, staged *stagedPowerShell, executionErr error) string {
	if staged == nil {
		return ""
	}
	if executionErr != nil {
		// Closing an SSH channel or sending SIGKILL is not proof that Windows
		// terminated the process. Let remote finally clean up after completion.
		return "remote completion was not confirmed; the temporary PowerShell script may remain until remote cleanup runs"
	}
	return cleanupStagedPowerShell(client, staged.remotePath, staged.executable)
}
