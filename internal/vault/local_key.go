package vault

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const localKeySize = 32

func initAutomaticStore(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("vault already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot open vault file")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("cannot create vault directory")
	}
	keyPath := path + ".key"
	if err := createLocalKey(keyPath); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("cannot create the local vault key")
	}
	key, err := readLocalKey(keyPath)
	if err != nil {
		return err
	}
	return createStore(ctx, path, 2, []byte{}, key)
}

func createLocalKey(path string) error {
	var raw [localKeySize]byte
	defer clear(raw[:])
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(raw[:]); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

func readLocalKey(path string) (cipher.AEAD, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("local vault key unavailable; restore the matching .key file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != localKeySize {
		return nil, fmt.Errorf("invalid local vault key")
	}
	var raw [localKeySize]byte
	defer clear(raw[:])
	if _, err := io.ReadFull(file, raw[:]); err != nil {
		return nil, fmt.Errorf("cannot read local vault key")
	}
	return aeadFromKey(raw[:]), nil
}

func (s *Store) automaticKey(ctx context.Context) (cipher.AEAD, error) {
	version, _, check, err := s.keyHeader(ctx)
	if err != nil || version == 1 {
		return nil, err
	}
	key, err := readLocalKey(s.Path + ".key")
	if err != nil {
		return nil, err
	}
	if !verifyKey(key, check) {
		return nil, fmt.Errorf("local vault key does not match this database")
	}
	return key, nil
}
