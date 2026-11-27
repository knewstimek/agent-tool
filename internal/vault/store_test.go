package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentVaultLifecycle(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "유저#vault", "profiles.sqlite")
	t.Setenv("AGENT_TOOL_VAULT_FILE", path)
	password := []byte("example-only long passphrase")
	if err := initStore(ctx, path, password); err != nil {
		t.Fatal(err)
	}
	s, err := open(path, "rw")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.unlock(ctx, []byte("wrong passphrase")); err == nil {
		t.Fatal("vault accepted wrong passphrase")
	}
	key, err := s.unlock(ctx, password)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		kind   string
		config Credentials
	}{
		{SSH, Credentials{Host: "ssh.example.invalid", User: "deploy", PrivateKey: "private-key-fixture-v1", Passphrase: "key-phrase-fixture"}},
		{MySQL, Credentials{Host: "db.example.invalid", User: "report", Password: "database-secret-fixture"}},
		{Cloudflare, Credentials{Token: "cloudflare-secret-fixture"}},
		{AWS, Credentials{AccessKeyID: "sample-id", SecretAccessKey: "aws-secret-fixture", SessionToken: "aws-session-fixture",
			Region: "us-east-1", Service: "sts", Endpoint: "https://sts.us-east-1.amazonaws.com"}},
	}
	for _, f := range fixtures {
		payload, err := json.Marshal(f.config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Decode(f.kind, payload); err != nil {
			t.Fatal(err)
		}
		p := Profile{Kind: f.kind, Name: "example", Metadata: Metadata{Tags: []string{"운영"}}}
		if rev, err := s.update(ctx, key, p, 0, payload, "put"); err != nil || rev != 1 {
			t.Fatalf("profile create revision %d: %v", rev, err)
		}
		if _, err := Resolve(ctx, f.kind, p.Name); !errors.Is(err, ErrLocked) {
			t.Fatalf("expected locked vault for %s, got %v", f.kind, err)
		}
	}
	list, err := s.Profiles(ctx, "", false)
	if err != nil || len(list) != 4 || list[0].Tags[0] != "운영" {
		t.Fatalf("locked catalog unavailable: %v", err)
	}

	sessionStore, err := open(path, "ro")
	if err != nil {
		t.Fatal(err)
	}
	defer sessionStore.Close()
	session, cancel := context.WithCancel(ctx)
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- serve(session, sessionStore, key, func() { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("could not unlock session: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("unlock session did not become available")
	}
	for _, f := range fixtures {
		c, err := Resolve(ctx, f.kind, "example")
		if err != nil || c != f.config {
			t.Fatalf("wrong resolved %s credential: %v", f.kind, err)
		}
	}

	p := Profile{Kind: Cloudflare, Name: "example", Metadata: Metadata{Description: "DNS access"}}
	if _, err := s.update(ctx, key, p, 0, nil, "metadata"); err == nil {
		t.Fatal("revision conflict was missed")
	}
	if rev, err := s.update(ctx, key, p, 1, nil, "metadata"); err != nil || rev != 2 {
		t.Fatalf("metadata revision %d: %v", rev, err)
	}
	if c, err := Resolve(ctx, Cloudflare, p.Name); err != nil || c.Token != "cloudflare-secret-fixture" {
		t.Fatalf("metadata update changed credential: %v", err)
	}
	onlyCredentials := Profile{Kind: p.Kind, Name: p.Name}
	if rev, err := s.update(ctx, key, onlyCredentials, 2, []byte(`{"token":"rotated-secret-fixture"}`), "put"); err != nil || rev != 3 {
		t.Fatalf("rotation revision %d: %v", rev, err)
	}
	if c, err := Resolve(ctx, Cloudflare, p.Name); err != nil || c.Token != "rotated-secret-fixture" {
		t.Fatalf("session did not pick up rotated credential: %v", err)
	}
	if rev, err := s.update(ctx, key, p, 3, nil, "delete"); err != nil || rev != 4 {
		t.Fatalf("deletion revision %d: %v", rev, err)
	}
	if _, err := Resolve(ctx, Cloudflare, p.Name); !errors.Is(err, ErrDeleted) {
		t.Fatalf("deleted profile still usable: %v", err)
	}
	history, err := s.history(ctx, p.Kind, p.Name)
	if err != nil || len(history) != 4 || history[0].Action != "delete" || history[1].Action != "replace" ||
		history[1].Description != "DNS access" || history[2].Action != "metadata" {
		t.Fatalf("incomplete revision history: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, "UPDATE profiles SET metadata = ? WHERE kind = 'mysql'", []byte(`{"description":"modified"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(ctx, MySQL, "example"); err == nil {
		t.Fatal("unauthenticated change to metadata did not invalidate decryption")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(ctx, SSH, "example"); !errors.Is(err, ErrLocked) {
		t.Fatalf("session remained unlocked: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"private-key-fixture-v1", "key-phrase-fixture", "database-secret-fixture",
		"cloudflare-secret-fixture", "aws-secret-fixture", "aws-session-fixture", "rotated-secret-fixture", string(password)} {
		if bytes.Contains(raw, []byte(text)) {
			t.Fatal("persisted database contains plaintext credential material")
		}
	}
}
