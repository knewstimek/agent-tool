package ssh

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPowerShellUploadValidatesInputAndNeverOverwrites(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows PowerShell upload test")
	}
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("Windows PowerShell unavailable")
	}
	for _, mode := range []string{"complete", "incomplete", "existing"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "script's content.ps1")
			content := []byte("\ufeffWrite-Output '한글 😀'")
			input := content
			wantExit := 0
			if mode == "incomplete" {
				input = content[:len(content)-3]
				wantExit = 1
			}
			if mode == "existing" {
				if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
					t.Fatal(err)
				}
				wantExit = 1
			}
			cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(powerShellUpload(path, len(content))))
			cmd.Stdin = strings.NewReader(base64.StdEncoding.EncodeToString(input))
			output, err := cmd.CombinedOutput()
			code := 0
			if err != nil {
				if e, ok := err.(*exec.ExitError); ok {
					code = e.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != wantExit {
				t.Fatalf("exit=%d want=%d output=%s", code, wantExit, output)
			}
			got, err := os.ReadFile(path)
			switch mode {
			case "complete":
				if err != nil || !bytes.Equal(got, content) {
					t.Fatalf("upload bytes changed: %v", err)
				}
			case "incomplete":
				if !os.IsNotExist(err) {
					t.Fatalf("partial upload created a file: %v", err)
				}
			case "existing":
				if err != nil || string(got) != "existing" {
					t.Fatalf("existing file was modified: %v", err)
				}
			}
		})
	}
}
