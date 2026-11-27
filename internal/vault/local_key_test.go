package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAutomaticVaultImportAndResolve(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "profiles.sqlite")
	t.Setenv("AGENT_TOOL_VAULT_FILE", path)
	const fixture = "example-ssh-fixture-password"
	record := SSHImportRecord{
		Profile:     Profile{Kind: SSH, Name: "preview"},
		Credentials: Credentials{Host: "example.invalid", User: "sample", Password: fixture},
	}
	if err := ImportSSH(ctx, []SSHImportRecord{record}); err != nil {
		t.Fatal(err)
	}
	credential, err := Resolve(ctx, SSH, "preview")
	if err != nil || credential.Password != fixture {
		t.Fatalf("automatic lookup failed: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte(fixture)) {
		t.Fatalf("unexpected vault contents: %v", err)
	}
	keyPath := path + ".key"
	key, err := os.ReadFile(keyPath)
	if err != nil || len(key) != localKeySize || bytes.Contains(raw, key) {
		t.Fatalf("local key does not remain separate: %v", err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x5a}, localKeySize), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(ctx, SSH, "preview"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key did not fail closed: %v", err)
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ImportSSH(ctx, []SSHImportRecord{record}); err != nil {
		t.Fatal(err)
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(gotKey, key) {
		t.Fatalf("re-import replaced the existing local key: %v", err)
	}
}
