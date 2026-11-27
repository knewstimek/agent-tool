// Package vault manages encrypted local connection profiles.
package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

var (
	ErrUninitialized = errors.New("vault is not initialized; run agent-tool vault init")
	ErrLocked        = errors.New("vault is locked; run agent-tool vault unlock in a local terminal")
	ErrNotFound      = errors.New("vault profile not found")
	ErrDeleted       = errors.New("vault profile was deleted")
)

const (
	SSH        = "ssh"
	MySQL      = "mysql"
	Cloudflare = "cloudflare"
	AWS        = "aws"
)

type Metadata struct {
	Description string   `json:"description,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type Profile struct {
	Kind     string `json:"kind"`
	Name     string `json:"connection_profile"`
	Revision int64  `json:"revision"`
	Removed  bool   `json:"-"`
	Metadata
}

type Revision struct {
	Profile
	Action string `json:"action"`
	At     string `json:"at"`
}

type Store struct {
	db   *sql.DB
	Path string
}

func Path() (string, error) {
	if custom := strings.TrimSpace(os.Getenv("AGENT_TOOL_VAULT_FILE")); custom != "" {
		if !filepath.IsAbs(custom) {
			return "", fmt.Errorf("AGENT_TOOL_VAULT_FILE must be absolute")
		}
		return filepath.Clean(custom), nil
	}
	dir := localDataDir()
	if dir == "" {
		var err error
		dir, err = os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("cannot find user configuration directory")
		}
	}
	return filepath.Join(dir, "agent-tool", "profiles.sqlite"), nil
}

func open(path, mode string) (*Store, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, ErrUninitialized
	} else if err != nil {
		return nil, fmt.Errorf("cannot open vault file")
	}
	name := filepath.ToSlash(path)
	if !strings.HasPrefix(name, "/") {
		name = "/" + name
	}
	u := url.URL{Scheme: "file", Path: name, RawQuery: "mode=" + mode + "&_pragma=busy_timeout(5000)&_txlock=immediate"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, fmt.Errorf("cannot open vault database")
	}
	db.SetMaxOpenConns(1)
	return &Store{db: db, Path: path}, nil
}

func Open() (*Store, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	return open(path, "ro")
}

func (s *Store) Close() error { return s.db.Close() }

func initStore(ctx context.Context, path string, password []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("cannot create vault directory")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("vault already exists")
	}
	if err != nil {
		return fmt.Errorf("cannot create vault file")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	ready := false
	defer func() {
		if !ready {
			_ = os.Remove(path)
		}
	}()
	store, err := open(path, "rw")
	if err != nil {
		return err
	}
	defer store.Close()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := makeAEAD(password, salt)
	check := key.Seal(nil, nil, []byte("agent-tool-vault-v1"), []byte("vault-key-check"))
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `
		CREATE TABLE vault_key (version INTEGER NOT NULL, salt BLOB NOT NULL, verifier BLOB NOT NULL);
		CREATE TABLE profiles (
			kind TEXT NOT NULL, name TEXT NOT NULL, revision INTEGER NOT NULL,
			metadata BLOB NOT NULL, ciphertext BLOB, PRIMARY KEY (kind, name)
		);
		CREATE TABLE revisions (
			kind TEXT NOT NULL, name TEXT NOT NULL, revision INTEGER NOT NULL,
			metadata BLOB NOT NULL, action TEXT NOT NULL, changed_at TEXT NOT NULL,
			PRIMARY KEY (kind, name, revision)
		);
	`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO vault_key VALUES (1, ?, ?)", salt, check); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	ready = true
	return nil
}

func makeAEAD(password, salt []byte) cipher.AEAD {
	key := argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		panic(err)
	}
	return aead
}

func (s *Store) unlock(ctx context.Context, password []byte) (cipher.AEAD, error) {
	var version int
	var salt, check []byte
	err := s.db.QueryRowContext(ctx, "SELECT version, salt, verifier FROM vault_key").Scan(&version, &salt, &check)
	if err != nil || version != 1 || len(salt) != 16 {
		return nil, fmt.Errorf("invalid vault database or unsupported version")
	}
	key := makeAEAD(password, salt)
	plain, err := key.Open(nil, nil, check, []byte("vault-key-check"))
	if err != nil || string(plain) != "agent-tool-vault-v1" {
		return nil, fmt.Errorf("wrong vault passphrase or damaged vault")
	}
	return key, nil
}

func validKind(kind string) bool {
	return kind == SSH || kind == MySQL || kind == Cloudflare || kind == AWS
}

func validName(name string) bool {
	return name != "" && len(name) <= 256 && name == strings.TrimSpace(name) && !strings.ContainsAny(name, "\x00\r\n")
}

func aad(kind, name string, revision int64, metadata []byte) []byte {
	return fmt.Appendf(nil, "agent-tool/v1:%s:%q:%d:%s", kind, name, revision, metadata)
}

func (s *Store) update(ctx context.Context, key cipher.AEAD, p Profile, expected int64, payload []byte, operation string) (int64, error) {
	if !validKind(p.Kind) || !validName(p.Name) || expected < 0 {
		return 0, fmt.Errorf("invalid kind, profile name, or expected revision")
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA secure_delete = ON"); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var prior int64
	var priorMetadata []byte
	var priorCiphertext []byte
	err = tx.QueryRowContext(ctx, "SELECT revision, metadata, ciphertext FROM profiles WHERE kind = ? AND name = ?", p.Kind, p.Name).
		Scan(&prior, &priorMetadata, &priorCiphertext)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if prior != expected {
		return 0, fmt.Errorf("revision conflict: current revision is %d", prior)
	}
	active := priorCiphertext != nil
	if operation != "put" && !active {
		return 0, ErrNotFound
	}
	revision := prior + 1
	metadata, err := json.Marshal(p.Metadata)
	if err != nil || len(metadata) > 4096 {
		return 0, fmt.Errorf("profile metadata exceeds 4096 bytes")
	}
	var ciphertext []byte
	action := "create"
	switch operation {
	case "delete":
		action, metadata = "delete", priorMetadata
	case "metadata":
		action = "metadata"
		plain, err := key.Open(nil, nil, priorCiphertext, aad(p.Kind, p.Name, prior, priorMetadata))
		if err != nil {
			return 0, fmt.Errorf("existing profile authentication failed")
		}
		defer clear(plain)
		ciphertext = key.Seal(nil, nil, plain, aad(p.Kind, p.Name, revision, metadata))
	default:
		if active {
			action = "replace"
			if p.Metadata.Description == "" && p.Metadata.Aliases == nil && p.Metadata.Tags == nil {
				metadata = priorMetadata
			}
		} else if prior > 0 {
			action = "restore"
		}
		ciphertext = key.Seal(nil, nil, payload, aad(p.Kind, p.Name, revision, metadata))
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO profiles VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(kind, name) DO UPDATE SET revision = excluded.revision,
			metadata = excluded.metadata, ciphertext = excluded.ciphertext
	`, p.Kind, p.Name, revision, metadata, ciphertext)
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO revisions VALUES (?, ?, ?, ?, ?, ?)", p.Kind, p.Name, revision, metadata, action, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return revision, tx.Commit()
}

func (s *Store) Profiles(ctx context.Context, kind string, includeDeleted bool) ([]Profile, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT kind, name, revision, metadata, ciphertext IS NULL FROM profiles WHERE (? = '' OR kind = ?) AND (? OR ciphertext IS NOT NULL) ORDER BY kind, name", kind, kind, includeDeleted)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	profiles := []Profile{}
	for rows.Next() {
		var p Profile
		var metadata []byte
		if err = rows.Scan(&p.Kind, &p.Name, &p.Revision, &metadata, &p.Removed); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(metadata, &p.Metadata); err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, rows.Err()
}

func (s *Store) history(ctx context.Context, kind, name string) ([]Revision, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT revision, metadata, action, changed_at FROM revisions WHERE kind = ? AND name = ? ORDER BY revision DESC", kind, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Revision{}
	for rows.Next() {
		r := Revision{Profile: Profile{Kind: kind, Name: name}}
		var metadata []byte
		if err = rows.Scan(&r.Revision, &metadata, &r.Action, &r.At); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(metadata, &r.Metadata); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

func (s *Store) ciphertext(ctx context.Context, kind, name string) (int64, []byte, []byte, error) {
	var revision int64
	var metadata, ciphertext []byte
	err := s.db.QueryRowContext(ctx, "SELECT revision, metadata, ciphertext FROM profiles WHERE kind = ? AND name = ?", kind, name).
		Scan(&revision, &metadata, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	} else if err == nil && ciphertext == nil {
		err = ErrDeleted
	}
	return revision, metadata, ciphertext, err
}
