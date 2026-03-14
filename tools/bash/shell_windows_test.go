//go:build windows

package bash

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestWrapWithTokenize(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"simple echo", "echo hello"},
		{"with semicolons", "echo a; echo b"},
		{"with pipe", "echo hello | grep h"},
		{"PS cmdlet", "Get-ChildItem -Path C:\\"},
		{"with quotes", `echo "hello world"`},
		{"with single quotes", `echo 'hello world'`},
		{"special chars", `echo $env:PATH; Write-Host "done"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wrapWithTokenize(tt.command)

			// Must contain Base64-encoded command
			b64 := base64.StdEncoding.EncodeToString([]byte(tt.command))
			if !strings.Contains(result, b64) {
				t.Errorf("result does not contain Base64 of command")
			}

			// Must contain Tokenize call
			if !strings.Contains(result, "PSParser]::Tokenize") {
				t.Errorf("result does not contain Tokenize call")
			}

			// Must contain Invoke-Expression
			if !strings.Contains(result, "Invoke-Expression") {
				t.Errorf("result does not contain Invoke-Expression")
			}

			// Must contain error handling path
			if !strings.Contains(result, "$global:LASTEXITCODE=1") {
				t.Errorf("result does not set LASTEXITCODE=1 on error")
			}

			// Wrapper must be pure ASCII (no raw user input leaked)
			for i, ch := range result {
				if ch > 127 {
					t.Errorf("non-ASCII char at pos %d: %q", i, string(ch))
					break
				}
			}
		})
	}
}

func TestBuildSentinelCmdPowerShell(t *testing.T) {
	sentinel := "===SENTINEL==="

	tests := []struct {
		name    string
		command string
	}{
		{"simple", "echo hello"},
		{"chain ops", "echo a && echo b"},
		{"nested chain", "$(cmd1 && cmd2)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSentinelCmd(kindPowerShell, tt.command, sentinel)

			// Sentinel must always be present — this is the key safety property
			if !strings.Contains(result, sentinel) {
				t.Errorf("sentinel missing from result")
			}

			// Must use Tokenize wrapper for PS 5.1
			if !strings.Contains(result, "PSParser]::Tokenize") {
				t.Errorf("PS 5.1 command not wrapped with Tokenize")
			}
		})
	}
}

func TestBuildSentinelCmdPwsh(t *testing.T) {
	sentinel := "===SENTINEL==="
	result := buildSentinelCmd(kindPwsh, "echo hello && echo world", sentinel)

	// pwsh (7+) should NOT use Tokenize — it handles && natively
	if strings.Contains(result, "Tokenize") {
		t.Errorf("pwsh should not use Tokenize wrapper")
	}
	if !strings.Contains(result, sentinel) {
		t.Errorf("sentinel missing from result")
	}
}
