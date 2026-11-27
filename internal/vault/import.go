package vault

import (
	"bytes"
	"context"
	"crypto/cipher"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

type SSHImportRecord struct {
	Profile     Profile
	Credentials Credentials
	KeyFile     string
	JumpKeyFile string
}

type preparedImport struct {
	profile    Profile
	metadata   []byte
	credential []byte
}

func ImportSSH(ctx context.Context, records []SSHImportRecord) error {
	items := make([]preparedImport, 0, len(records))
	defer func() {
		for _, item := range items {
			clear(item.credential)
		}
	}()
	for i, record := range records {
		item, err := prepareSSHImport(record)
		if err != nil {
			return fmt.Errorf("cannot import source entry %d: %w", i+1, err)
		}
		items = append(items, item)
	}
	path, err := Path()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Ready to copy %d SSH profiles. Original files are kept.\n", len(items))
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		password, err := readHidden("New vault passphrase")
		if err != nil {
			return err
		}
		defer clear(password)
		if len(password) < 14 {
			return fmt.Errorf("use a vault passphrase of at least 14 bytes")
		}
		confirm, err := readHidden("Confirm vault passphrase")
		if err != nil {
			return err
		}
		defer clear(confirm)
		if !bytes.Equal(password, confirm) {
			return fmt.Errorf("passphrases do not match")
		}
		if err := initStore(ctx, path, password); err != nil {
			return err
		}
		return finishSSHImport(ctx, path, password, items)
	}
	password, err := readHidden("Vault passphrase")
	if err != nil {
		return err
	}
	defer clear(password)
	return finishSSHImport(ctx, path, password, items)
}

func prepareSSHImport(record SSHImportRecord) (preparedImport, error) {
	p, c := record.Profile, record.Credentials
	if !validName(p.Name) || p.Kind != SSH {
		return preparedImport{}, fmt.Errorf("invalid encrypted profile name")
	}
	for _, entry := range []struct {
		path string
		key  *string
	}{{record.KeyFile, &c.PrivateKey}, {record.JumpKeyFile, &c.JumpPrivateKey}} {
		if entry.path != "" {
			data, err := readLocalFile(entry.path)
			if err != nil || len(data) == 0 {
				return preparedImport{}, fmt.Errorf("a referenced private key file could not be read")
			}
			*entry.key = string(data)
			clear(data)
		}
	}
	if c.PrivateKey == "" {
		c.Passphrase = ""
	}
	if c.JumpHost != "" {
		if c.JumpPrivateKey == "" {
			c.JumpPrivateKey = c.PrivateKey
		}
		if c.JumpPassphrase == "" {
			c.JumpPassphrase = c.Passphrase
		}
		if c.JumpPassword == "" {
			c.JumpPassword = c.Password
		}
	}
	if c.JumpPrivateKey == "" {
		c.JumpPassphrase = ""
	}
	metadata, err := json.Marshal(p.Metadata)
	if err != nil || len(metadata) > 4096 {
		return preparedImport{}, fmt.Errorf("profile metadata exceeds 4096 bytes")
	}
	payload, err := json.Marshal(c)
	if err != nil || len(payload) > maxPayload {
		clear(payload)
		return preparedImport{}, fmt.Errorf("profile credential data exceeds 256 KiB")
	}
	if _, err := Decode(SSH, payload); err != nil {
		clear(payload)
		return preparedImport{}, err
	}
	return preparedImport{profile: p, metadata: metadata, credential: payload}, nil
}

func finishSSHImport(ctx context.Context, path string, password []byte, items []preparedImport) error {
	store, err := open(path, "rw")
	if err != nil {
		return err
	}
	defer store.Close()
	key, err := store.unlock(ctx, password)
	if err != nil {
		return err
	}
	added, unchanged, err := store.importSSH(ctx, key, items)
	if err != nil {
		return err
	}
	return printJSON(map[string]int{"imported": added, "unchanged": unchanged, "verified": added + unchanged})
}

func (s *Store) importSSH(ctx context.Context, key cipher.AEAD, items []preparedImport) (added, unchanged int, _ error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	at := time.Now().UTC().Format(time.RFC3339Nano)
	for i, item := range items {
		name := item.profile.Name
		var prior int64
		var metadata, ciphertext []byte
		err = tx.QueryRowContext(ctx, "SELECT revision, metadata, ciphertext FROM profiles WHERE kind = ? AND name = ?", SSH, name).
			Scan(&prior, &metadata, &ciphertext)
		switch {
		case err == nil:
			proof, openErr := key.Open(nil, nil, ciphertext, aad(SSH, name, prior, metadata))
			matches := openErr == nil && bytes.Equal(proof, item.credential) && bytes.Equal(metadata, item.metadata)
			clear(proof)
			if !matches {
				return 0, 0, fmt.Errorf("encrypted profile conflict at source entry %d; existing profiles were kept", i+1)
			}
			unchanged++
		case errors.Is(err, sql.ErrNoRows):
			encrypted := key.Seal(nil, nil, item.credential, aad(SSH, name, 1, item.metadata))
			if _, err = tx.ExecContext(ctx, "INSERT INTO profiles VALUES (?, ?, 1, ?, ?)", SSH, name, item.metadata, encrypted); err != nil {
				return 0, 0, err
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO revisions VALUES (?, ?, 1, ?, 'create', ?)", SSH, name, item.metadata, at); err != nil {
				return 0, 0, err
			}
			var saved []byte
			if err = tx.QueryRowContext(ctx, "SELECT ciphertext FROM profiles WHERE kind = ? AND name = ?", SSH, name).Scan(&saved); err != nil {
				return 0, 0, err
			}
			proof, err := key.Open(nil, nil, saved, aad(SSH, name, 1, item.metadata))
			matches := err == nil && bytes.Equal(proof, item.credential)
			clear(proof)
			if !matches {
				return 0, 0, fmt.Errorf("could not verify encrypted profile at source entry %d", i+1)
			}
			added++
		default:
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return added, unchanged, nil
}
