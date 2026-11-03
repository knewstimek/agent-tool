package common

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestSnapshotHashAndStaleWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "legacy.txt")
	raw := []byte{0xb0, 0xa1, '\r', '\n'}
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	text, info, err := ReadFileWithEncodingHash(p, "CP949")
	if err != nil || text != "\uac00\r\n" || info.RawSHA256 != fmt.Sprintf("%x", sha256.Sum256(raw)) || info.RawSize != int64(len(raw)) {
		t.Fatalf("snapshot: %q %+v %v", text, info, err)
	}
	if err := os.WriteFile(p, []byte("external change"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileWithEncoding(p, "new", info); err == nil {
		t.Fatal("stale snapshot overwrote new content")
	}
	got, _ := os.ReadFile(p)
	if string(got) != "external change" {
		t.Fatal("stale write changed file")
	}
}

func TestConcurrentSnapshotWritersDoNotLoseUpdate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "text.txt")
	if err := os.WriteFile(p, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	_, info, err := ReadFileWithEncodingHash(p, "")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for _, text := range []string{"first", "second"} {
		go func(text string) { ready.Done(); <-start; results <- WriteFileWithEncoding(p, text, info) }(text)
	}
	ready.Wait()
	close(start)
	success := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful stale-snapshot writes=%d want=1", success)
	}
}
