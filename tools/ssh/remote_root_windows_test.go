package ssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWindowsRemoteRootExecutionAndFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root with spaces")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	for _, shell := range []string{"cmd", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			for _, missing := range []bool{false, true} {
				cwd := root
				if missing {
					cwd = filepath.Join(root, "missing")
				}
				in := SSHInput{RemoteRoot: cwd, RemoteShell: shell}
				if shell == "cmd" {
					in.Command = "cd & echo ROOT_OK"
				} else {
					in.Command = "(Get-Location).Path; Write-Output ROOT_OK"
				}
				if err := normalizeRemoteRoot(&in); err != nil {
					t.Fatal(err)
				}
				applyRemoteRoot(&in)
				var command *exec.Cmd
				if shell == "cmd" {
					// cmd does not use CommandLineToArgvW quoting. Supply the same raw
					// /c command string a Windows SSH default shell receives.
					command = exec.Command("cmd.exe")
					command.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd.exe /d /s /c "` + in.Command + `"`}
				} else {
					command = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(in.Command))
				}
				out, err := command.CombinedOutput()
				if missing {
					if err == nil || strings.Contains(string(out), "ROOT_OK") {
						t.Fatalf("ran after failed cd: err=%v out=%s", err, out)
					}
				} else if err != nil || !strings.Contains(string(out), "ROOT_OK") || !strings.Contains(string(out), root) {
					t.Fatalf("cwd/execution failed: err=%v out=%s", err, out)
				}
			}
		})
	}
}
