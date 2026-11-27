package vault

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const maxPayload = 256 * 1024

type lookup struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

func sessionID(path string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(path)))[:24]
}

func Resolve(ctx context.Context, kind, name string) (Credentials, error) {
	payload, err := load(ctx, kind, name)
	if err != nil {
		return Credentials{}, err
	}
	defer clear(payload)
	return Decode(kind, payload)
}

func load(ctx context.Context, kind, name string) ([]byte, error) {
	if !validKind(kind) || !validName(name) {
		return nil, ErrNotFound
	}
	store, err := Open()
	if err != nil {
		return nil, err
	}
	defer store.Close()
	revision, metadata, ciphertext, err := store.ciphertext(ctx, kind, name)
	if err != nil {
		return nil, err
	}
	key, err := store.automaticKey(ctx)
	if err != nil {
		return nil, err
	}
	if key != nil {
		payload, err := key.Open(nil, nil, ciphertext, aad(kind, name, revision, metadata))
		if err != nil {
			return nil, fmt.Errorf("vault profile authentication failed")
		}
		return payload, nil
	}
	path := store.Path
	body, err := json.Marshal(lookup{kind, name})
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialSession(ctx, sessionID(path))
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://vault.local/use", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrLocked
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault could not decrypt the selected profile; check its current revision and unlock again")
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxPayload+1))
	if err != nil || len(payload) > maxPayload {
		return nil, fmt.Errorf("invalid response from vault session")
	}
	return payload, nil
}

func serve(ctx context.Context, s *Store, key cipher.AEAD, ready func()) error {
	listener, err := listenSession(sessionID(s.Path))
	if err != nil {
		return fmt.Errorf("cannot start vault session: %w", err)
	}
	defer listener.Close()
	server := &http.Server{
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 4096,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/use" || !strings.EqualFold(r.Host, "vault.local") || r.Header.Get("Origin") != "" {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			var p lookup
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&p); err != nil || !validKind(p.Kind) || !validName(p.Name) {
				http.Error(w, "invalid lookup", http.StatusBadRequest)
				return
			}
			revision, metadata, encrypted, err := s.ciphertext(r.Context(), p.Kind, p.Name)
			if err != nil {
				http.Error(w, "profile unavailable", http.StatusNotFound)
				return
			}
			plaintext, err := key.Open(nil, nil, encrypted, aad(p.Kind, p.Name, revision, metadata))
			if err != nil {
				http.Error(w, "profile authentication failed", http.StatusConflict)
				return
			}
			defer clear(plaintext)
			if ctx.Err() != nil {
				http.Error(w, "vault locked", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(plaintext)
		}),
	}
	stop := context.AfterFunc(ctx, func() {
		_ = server.Close()
		_ = listener.Close()
	})
	defer stop()
	ready()
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
		return err
	}
	return nil
}
