package ssh

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPowerShellPlan(t *testing.T) {
	script := strings.Repeat("# padding\n", 400) + "Write-Output '한글 😀'"
	command := "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -enc " + encodePowerShell(script)
	plan, err := planPowerShell(SSHInput{Command: command})
	if err != nil || plan == nil || plan.script != script || !strings.Contains(plan.prefix, "-ExecutionPolicy Bypass") {
		t.Fatalf("long EncodedCommand was not preserved: plan=%v err=%v", plan, err)
	}
	for _, command := range []string{"echo " + strings.Repeat("x", 9000), "powershell.exe -enc " + encodePowerShell("echo short")} {
		plan, err := planPowerShell(SSHInput{Command: command})
		if err != nil || plan != nil {
			t.Fatalf("unrelated or short command was rewritten: %v %v", plan, err)
		}
	}
	for _, suffix := range []string{" & echo injected", " > output.txt", " extra"} {
		if _, err := planPowerShell(SSHInput{Command: command + suffix}); err == nil {
			t.Fatalf("shell suffix %q should require explicit script input", suffix)
		}
	}
	if _, err := planPowerShell(SSHInput{Command: "echo x", PowerShellScript: "echo y"}); err == nil {
		t.Fatal("ambiguous input accepted")
	}
	if _, err := planPowerShell(SSHInput{PowerShellScript: strings.Repeat("x", maxPowerShellScriptBytes+1)}); err == nil {
		t.Fatal("oversized script accepted")
	}
	invalid := base64.StdEncoding.EncodeToString([]byte{0, 0xd8}) // unpaired UTF-16 surrogate
	if _, err := planPowerShell(SSHInput{Command: "powershell.exe " + strings.Repeat("-nop ", 1700) + "-enc " + invalid}); err == nil {
		t.Fatal("malformed UTF-16 accepted")
	}
}

func TestPowerShellBootstrapPreservesExecutionAndCleans(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows PowerShell execution test")
	}
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("Windows PowerShell is unavailable")
	}
	for _, tt := range []struct {
		name, script, output string
		exit                 int
	}{
		{"unicode", "Write-Output '한글 😀'", "한글 😀", 0},
		{"explicit exit", "Write-Output 'before'; exit 23", "before", 23},
		{"terminating error", "throw 'expected failure'", "", 1},
		{"nonterminating error", "Write-Error 'expected failure'", "", 1},
		{"syntax error", "if (", "", 1},
		{"native exit", "cmd.exe /c exit 7", "", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Quotes and spaces exercise literal-path handling.
			path := filepath.Join(t.TempDir(), "script's content.ps1")
			if err := os.WriteFile(path, []byte("\ufeff"+tt.script), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(powerShellBootstrap(path)))
			output, err := cmd.CombinedOutput()
			code := 0
			if err != nil {
				if e, ok := err.(*exec.ExitError); ok {
					code = e.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != tt.exit || (tt.output != "" && !strings.Contains(string(output), tt.output)) {
				t.Fatalf("exit=%d want=%d output=%s", code, tt.exit, output)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("temporary script remained after %s: %v", tt.name, err)
			}
		})
	}
}

func TestUnconfirmedPowerShellCompletionDoesNotDelete(t *testing.T) {
	staged := &stagedPowerShell{remotePath: "unused"}
	warning := finishStagedPowerShell(nil, staged, context.Canceled)
	if !strings.Contains(warning, "not confirmed") {
		t.Fatalf("missing cancellation warning: %q", warning)
	}
}
