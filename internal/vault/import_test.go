package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSSHImportKeepsSourcesAndRollsBackOnConflict(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.sqlite")
	sourceKey := filepath.Join(dir, "source-key")
	testKey := []byte("private-import-fixture")
	if err := os.WriteFile(sourceKey, testKey, 0600); err != nil {
		t.Fatal(err)
	}
	password := []byte("sample-only vault passphrase")
	if err := initStore(ctx, path, password); err != nil {
		t.Fatal(err)
	}
	store, err := open(path, "rw")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key, err := store.unlock(ctx, password)
	if err != nil {
		t.Fatal(err)
	}
	record := SSHImportRecord{
		Profile:     Profile{Kind: SSH, Name: "legacy-vault"},
		Credentials: Credentials{Host: "example.invalid", User: "example", JumpHost: "bastion.example.invalid", Passphrase: "fixture-pass"},
		KeyFile:     sourceKey,
	}
	item, err := prepareSSHImport(record)
	if err != nil {
		t.Fatal(err)
	}
	config, err := Decode(SSH, item.credential)
	if err != nil || config.PrivateKey != string(testKey) || config.JumpPrivateKey != config.PrivateKey || config.JumpPassphrase != config.Passphrase {
		t.Fatalf("key or jump settings did not migrate: %v", err)
	}
	if added, unchanged, err := store.importSSH(ctx, key, []preparedImport{item}); err != nil || added != 1 || unchanged != 0 {
		t.Fatalf("initial import = %d/%d: %v", added, unchanged, err)
	}
	if added, unchanged, err := store.importSSH(ctx, key, []preparedImport{item}); err != nil || added != 0 || unchanged != 1 {
		t.Fatalf("repeat import = %d/%d: %v", added, unchanged, err)
	}
	newRecord := record
	newRecord.Profile.Name = "new-vault"
	newItem, err := prepareSSHImport(newRecord)
	if err != nil {
		t.Fatal(err)
	}
	record.Credentials.User = "other"
	conflict, err := prepareSSHImport(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.importSSH(ctx, key, []preparedImport{newItem, conflict}); err == nil {
		t.Fatal("import overwrote existing profile")
	}
	list, err := store.Profiles(ctx, SSH, false)
	if err != nil || len(list) != 1 || list[0].Name != "legacy-vault" {
		t.Fatalf("failed import left partial changes: %v", err)
	}
	raw, err := os.ReadFile(sourceKey)
	if err != nil || !bytes.Equal(raw, testKey) {
		t.Fatalf("original key was changed: %v", err)
	}
	disk, err := os.ReadFile(path)
	if err != nil || bytes.Contains(disk, testKey) || bytes.Contains(disk, []byte(sourceKey)) {
		t.Fatalf("plaintext private key or key path in database: %v", err)
	}
}
