package common

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type echTestTransport func(*http.Request) (*http.Response, error)

func (f echTestTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestECHFallsBackWithoutRepeatingSentChanges(t *testing.T) {
	disconnected := io.ErrUnexpectedEOF
	rejected := &url.Error{Op: "Post", Err: &tls.ECHRejectionError{}}
	for _, tc := range []struct {
		name   string
		method string
		err    error
		sent   bool
		retry  bool
	}{
		{"lost POST response", http.MethodPost, disconnected, true, false},
		{"unknown POST transport error", http.MethodPost, disconnected, false, false},
		{"ECH rejected before upload", http.MethodPost, rejected, false, true},
		{"ECH rejected after a redirect", http.MethodPost, rejected, true, false},
		{"retry download", http.MethodGet, disconnected, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), tc.method, "https://example.invalid", strings.NewReader("fixture-body"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(req.Body); err != nil {
				t.Fatal(err)
			}
			req.Body.Close()
			calls := 0
			client := &http.Client{Transport: echTestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(req.Body)
				req.Body.Close()
				if err != nil || string(body) != "fixture-body" {
					t.Fatalf("retry did not reopen the request body: %v", err)
				}
				return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
			})}
			resp, err := retryWithoutECH(client, req, tc.err, tc.sent)
			if tc.retry {
				if calls != 1 || resp == nil || err != nil {
					t.Fatalf("expected a single fallback, got %d: %v", calls, err)
				}
				resp.Body.Close()
			} else if calls != 0 || resp != nil || !errors.Is(err, tc.err) {
				t.Fatalf("unexpected request replay or original error lost: %d (%v)", calls, err)
			}
		})
	}
}
