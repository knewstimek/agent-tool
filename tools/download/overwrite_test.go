package download

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"agent-tool/common"
)

func TestDownloadPreservesConcurrentDestination(t *testing.T) {
	previous := common.GetAllowHTTPPrivate()
	common.SetAllowHTTPPrivate(true)
	t.Cleanup(func() { common.SetAllowHTTPPrivate(previous) })
	for _, overwrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "no_overwrite", true: "overwrite"}[overwrite], func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "download.txt")
			writeErrors := make(chan error, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeErrors <- os.WriteFile(p, []byte("created during request"), 0600)
				_, _ = w.Write([]byte("downloaded"))
			}))
			defer server.Close()
			result, _, err := Handle(context.Background(), nil, DownloadInput{
				URL: server.URL, OutputPath: p, Overwrite: overwrite, NoDoH: true, NoECH: true,
			})
			if writeErr := <-writeErrors; writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil || result.IsError == overwrite {
				t.Fatalf("unexpected download result: err=%v result=%+v", err, result)
			}
			want := "created during request"
			if overwrite {
				want = "downloaded"
			}
			got, err := os.ReadFile(p)
			if err != nil || string(got) != want {
				t.Fatalf("concurrent destination lost: got=%q want=%q err=%v", got, want, err)
			}
			staged, err := filepath.Glob(filepath.Join(filepath.Dir(p), ".agent-tool-download-*.tmp"))
			if err != nil || len(staged) != 0 {
				t.Fatalf("staging files leaked: %v err=%v", staged, err)
			}
		})
	}
}

func TestDownloadCreatesAbsentDestination(t *testing.T) {
	previous := common.GetAllowHTTPPrivate()
	common.SetAllowHTTPPrivate(true)
	t.Cleanup(func() { common.SetAllowHTTPPrivate(previous) })
	p := filepath.Join(t.TempDir(), "new.txt")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("downloaded"))
	}))
	defer server.Close()
	result, _, err := Handle(context.Background(), nil, DownloadInput{URL: server.URL, OutputPath: p, NoDoH: true, NoECH: true})
	if err != nil || result.IsError {
		t.Fatalf("new download failed: %v %+v", err, result)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "downloaded" {
		t.Fatalf("new download bytes: %q %v", got, err)
	}
	staged, err := filepath.Glob(filepath.Join(filepath.Dir(p), ".agent-tool-download-*.tmp"))
	if err != nil || len(staged) != 0 {
		t.Fatalf("staging files leaked: %v err=%v", staged, err)
	}
}
