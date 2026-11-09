package ssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runRootedWindows(t *testing.T, input SSHInput, initial string) ([]byte, error) {
	t.Helper()
	if err := normalizeRemoteRoot(&input); err != nil {
		t.Fatal(err)
	}
	command, plan, err := prepareSSHExecution(input)
	if err != nil {
		t.Fatal(err)
	}
	var encoded string
	if plan != nil {
		scriptPath := filepath.Join(t.TempDir(), "payload.ps1")
		if err := os.WriteFile(scriptPath, append([]byte{0xef, 0xbb, 0xbf}, []byte(plan.script)...), 0600); err != nil {
			t.Fatal(err)
		}
		encoded = encodePowerShell(powerShellBootstrapRoot(scriptPath, plan.remoteRoot))
	} else {
		if strings.HasPrefix(command, defaultPowerShellPrefix) {
			encoded = strings.TrimPrefix(command, defaultPowerShellPrefix)
		} else {
			encoded = encodePowerShell(command)
		}
	}
	process := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
	process.Dir = initial
	return process.CombinedOutput()
}

func TestWindowsRemoteRootExecutionAndFailure(t *testing.T) {
	initial := t.TempDir()
	root := filepath.Join(initial, "root with spaces")
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
				input := SSHInput{RemoteRoot: cwd, RemoteShell: shell}
				if shell == "cmd" {
					input.Command = "echo %CD% & echo ROOT_OK"
				} else {
					input.Command = "(Get-Location).Path; Write-Output ROOT_OK"
				}
				out, err := runRootedWindows(t, input, initial)
				if missing {
					if err == nil || strings.Contains(string(out), "ROOT_OK") {
						t.Fatalf("ran after failed cwd: %v %s", err, out)
					}
				} else if err != nil || !strings.Contains(string(out), "ROOT_OK") || !strings.Contains(string(out), root) {
					t.Fatalf("cwd/expansion failed: %v %s", err, out)
				}
			}
		})
	}
}

func TestCMDRemoteRootCannotEscapeDirectoryFailure(t *testing.T) {
	initial := t.TempDir()
	for _, command := range []string{"echo hello) & echo SHOULD_NOT_RUN", "echo x & echo SHOULD_NOT_RUN", "echo x | echo SHOULD_NOT_RUN", "echo ^) & echo SHOULD_NOT_RUN", "exit /b 0"} {
		out, err := runRootedWindows(t, SSHInput{RemoteRoot: filepath.Join(initial, "missing"), RemoteShell: "cmd", Command: command}, initial)
		if err == nil || strings.Contains(string(out), "SHOULD_NOT_RUN") {
			t.Fatalf("cwd bypass for %q: %v %s", command, err, out)
		}
	}
	out, err := runRootedWindows(t, SSHInput{RemoteRoot: initial, RemoteShell: "cmd", Command: "exit /b 23"}, initial)
	if status, ok := err.(*exec.ExitError); !ok || status.ExitCode() != 23 {
		t.Fatalf("lost child exit: %v %s", err, out)
	}
}

func TestPowerShellRemoteRootPreservesLeadingDeclarations(t *testing.T) {
	initial := t.TempDir()
	root := filepath.Join(initial, "root's files")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	script := `using namespace System.Text
param([string]$value='SCRIPT_OK')
[StringBuilder]::new($value).ToString(); (Get-Location).Path`
	for _, explicit := range []bool{false, true} {
		input := SSHInput{RemoteRoot: root, RemoteShell: "powershell"}
		if explicit {
			input.PowerShellScript = script
		} else {
			input.Command = script
		}
		out, err := runRootedWindows(t, input, initial)
		if err != nil || !strings.Contains(string(out), "SCRIPT_OK") || !strings.Contains(string(out), root) {
			t.Fatalf("declarations/cwd lost: %v %s", err, out)
		}
		input.RemoteRoot = filepath.Join(root, "missing")
		out, err = runRootedWindows(t, input, initial)
		if err == nil || strings.Contains(string(out), "SCRIPT_OK") {
			t.Fatalf("script ran after cwd failure: %v %s", err, out)
		}
	}
}

func TestPowerShellRootLengthTriggersStaging(t *testing.T) {
	initial := t.TempDir()
	root := filepath.Join(initial, strings.Repeat("r", 140))
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	original := defaultPowerShellPrefix + encodePowerShell("Write-Output 'STAGE_OK';#"+strings.Repeat("x", 2920))
	if len(original) >= powerShellInlineLimit || len(original) < 7800 {
		t.Fatalf("fixture length=%d", len(original))
	}
	input := SSHInput{RemoteRoot: root, RemoteShell: "cmd", Command: original}
	if err := normalizeRemoteRoot(&input); err != nil {
		t.Fatal(err)
	}
	_, plan, err := prepareSSHExecution(input)
	if err != nil || plan == nil {
		t.Fatalf("final launcher not staged: %v", err)
	}
	out, err := runRootedWindows(t, input, initial)
	if err != nil || !strings.Contains(string(out), "STAGE_OK") {
		t.Fatalf("staged command failed: %v %s", err, out)
	}
	// Long auto-decoded PowerShell scripts must keep declarations at their start.
	script := `using namespace System.Text
[StringBuilder]::new('AUTO_OK').ToString();#` + strings.Repeat("x", 3100)
	input = SSHInput{RemoteRoot: root, RemoteShell: "cmd", Command: defaultPowerShellPrefix + encodePowerShell(script)}
	_, plan, err = prepareSSHExecution(input)
	if err != nil || plan == nil || plan.script != script {
		t.Fatalf("auto staging changed script: %v", err)
	}
	out, err = runRootedWindows(t, input, initial)
	if err != nil || !strings.Contains(string(out), "AUTO_OK") {
		t.Fatalf("auto-staged declaration failed: %v %s", err, out)
	}
}
