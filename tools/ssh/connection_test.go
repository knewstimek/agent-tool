package ssh

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-tool/internal/vault"
)

func newVaultSSHFixture(t *testing.T) (credentialsFile, legacyFile string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AGENT_TOOL_VAULT_FILE", filepath.Join(dir, "profiles.sqlite"))
	legacyFile = filepath.Join(dir, "connections.json")
	t.Setenv("AGENT_TOOL_CONNECTION_PROFILE_FILE", legacyFile)
	data := []byte(`{"connections":{"shared":{"host":"legacy.example.invalid","user":"example"}}}`)
	if err := os.WriteFile(legacyFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "input.json"), legacyFile
}

func putVaultSSHFixture(t *testing.T, file, host, revision string) {
	t.Helper()
	payload, err := json.Marshal(vault.Credentials{Host: host, User: "example", UseAgent: true, RemoteRoot: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := vault.RunCLI(t.Context(), []string{"put", "ssh", "shared-vault", "--input", file, "--revision", revision}); err != nil {
		t.Fatal(err)
	}
}

func TestVaultConnectionIDDoesNotFollowProfileChange(t *testing.T) {
	file, _ := newVaultSSHFixture(t)
	putVaultSSHFixture(t, file, "one.example.invalid", "0")
	first := SSHInput{ConnectionProfile: "shared-vault", RemoteRoot: "/override"}
	id, err := ResolveConnection(&first)
	if err != nil || first.Host != "one.example.invalid" {
		t.Fatalf("could not establish initial connection id: %v", err)
	}
	if err := vault.RunCLI(t.Context(), []string{"metadata", "ssh", "shared-vault", "--revision", "1", "--tag", "updated"}); err != nil {
		t.Fatal(err)
	}
	same := SSHInput{ConnectionID: id}
	if got, err := ResolveConnection(&same); err != nil || got != id || same.RemoteRoot != "/override" {
		t.Fatalf("metadata-only edit changed the existing connection: %v", err)
	}
	putVaultSSHFixture(t, file, "two.example.invalid", "2")
	stale := SSHInput{ConnectionID: id}
	if _, err := ResolveConnection(&stale); err == nil || !strings.Contains(err.Error(), "connection profile changed") || stale.Host != "" {
		t.Fatal("stale connection id did not fail before resolving another host")
	}
	newConnection := SSHInput{ConnectionProfile: "shared-vault"}
	if replacement, err := ResolveConnection(&newConnection); err != nil || replacement == id || newConnection.Host != "two.example.invalid" || newConnection.RemoteRoot != "/work" {
		t.Fatalf("profile could not issue a new connection id: %v", err)
	}
}

func TestVaultSearchPrefersEncryptedAndSurvivesLegacyFailure(t *testing.T) {
	file, legacy := newVaultSSHFixture(t)
	putVaultSSHFixture(t, file, "one.example.invalid", "0")
	query := profileSearchInput{Query: "shared", Kind: "ssh", Limit: 1}
	_, result, err := handleProfileSearch(t.Context(), nil, query)
	if err != nil || result.Total != 2 || result.NextOffset != 1 || len(result.Profiles) != 1 || result.Profiles[0].Storage != storageVault || result.Profiles[0].ConnectionProfile != "shared-vault" {
		t.Fatalf("encrypted copy was not first: %+v (%v)", result, err)
	}
	query.Offset = result.NextOffset
	_, result, err = handleProfileSearch(t.Context(), nil, query)
	if err != nil || len(result.Profiles) != 1 || result.Profiles[0].Storage != storageLegacy || result.Profiles[0].ConnectionProfile != "shared" {
		t.Fatalf("legacy profile was missing from the next page: %+v (%v)", result, err)
	}
	query.Offset, query.Storage = 0, storageLegacy
	_, result, err = handleProfileSearch(t.Context(), nil, query)
	if err != nil || result.Total != 1 || len(result.Profiles) != 1 || result.Profiles[0].Storage != storageLegacy {
		t.Fatalf("legacy filter was not applied: %+v (%v)", result, err)
	}
	if err := os.Remove(legacy); err != nil {
		t.Fatal(err)
	}
	query.Storage = ""
	_, result, err = handleProfileSearch(t.Context(), nil, query)
	if err != nil || len(result.Profiles) != 1 || result.Profiles[0].Storage != storageVault || len(result.Warnings) != 1 {
		t.Fatalf("legacy failure hid the valid vault results: %+v (%v)", result, err)
	}
	query.Storage = storageVault
	_, result, err = handleProfileSearch(t.Context(), nil, query)
	if err != nil || len(result.Profiles) != 1 || len(result.Warnings) != 0 {
		t.Fatalf("vault-only search depended on the legacy file: %+v (%v)", result, err)
	}
	query.Storage = storageLegacy
	if _, _, err := handleProfileSearch(t.Context(), nil, query); err == nil {
		t.Fatal("legacy-only search hid its source failure")
	}
}

func TestLocalConnectionProfileAndConnectionIDReuse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "connections.json")
	data := []byte(`{"connections":{"dev":{"host":"127.0.0.1","port":2222,"user":"builder","key_file":"~/.ssh/id_test","trusted":true}}}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_TOOL_CONNECTION_PROFILE_FILE", path)

	first := SSHInput{ConnectionProfile: "dev"}
	id, err := ResolveConnection(&first)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "conn_") || first.Host != "127.0.0.1" || first.User != "builder" || !first.TrustedProfile {
		t.Fatalf("profile was not resolved: id=%q input=%+v", id, first)
	}

	second := SSHInput{ConnectionID: id}
	secondID, err := ResolveConnection(&second)
	if err != nil {
		t.Fatal(err)
	}
	if secondID != id || second.Host != first.Host || second.User != first.User || !second.TrustedProfile {
		t.Fatalf("connection handle was not reused: id=%q input=%+v", secondID, second)
	}

	again := SSHInput{ConnectionProfile: "dev"}
	againID, err := ResolveConnection(&again)
	if err != nil || againID != id {
		t.Fatalf("same profile should reuse its handle: id=%q err=%v", againID, err)
	}
}

func TestLocalConnectionProfileTrustedDefaultsTrue(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		trusted bool
	}{
		{name: "omitted", profile: `{"host":"127.0.0.1","user":"builder"}`, trusted: true},
		{name: "explicit true", profile: `{"host":"127.0.0.1","user":"builder","trusted":true}`, trusted: true},
		{name: "explicit false", profile: `{"host":"127.0.0.1","user":"builder","trusted":false}`, trusted: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var profile ConnectionProfile
			if err := json.Unmarshal([]byte(tt.profile), &profile); err != nil {
				t.Fatal(err)
			}
			if profile.Trusted != tt.trusted {
				t.Fatalf("trusted = %v, want %v", profile.Trusted, tt.trusted)
			}
		})
	}
}

func TestTrustedPrivateWarningIsOncePerPooledSession(t *testing.T) {
	input := SSHInput{Host: "127.0.0.1", User: "builder", HostKeyCheck: "none", TrustedProfile: true}
	if err := validateInput(&input); err != nil {
		t.Fatal(err)
	}
	key := sessionKey(input)
	pool.mu.Lock()
	pool.sessions[key] = &sessionEntry{}
	pool.mu.Unlock()
	t.Cleanup(func() {
		pool.mu.Lock()
		delete(pool.sessions, key)
		pool.mu.Unlock()
	})

	warning := "private address warning"
	if got := PrivateWarningForConnection(input, warning); got != warning {
		t.Fatalf("first warning = %q", got)
	}
	if got := PrivateWarningForConnection(input, warning); got != "" {
		t.Fatalf("second warning = %q", got)
	}

	input.TrustedProfile = false
	if got := PrivateWarningForConnection(input, warning); got != warning {
		t.Fatalf("untrusted warning should not be suppressed: %q", got)
	}
}
