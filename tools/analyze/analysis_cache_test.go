package analyze

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestAnalysisCacheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.bin")
	want := []uint64{1, 0x140001000, ^uint64(0)}
	storeUint64s(path, want)
	got, ok := loadUint64s(path)
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %v, %v; want %v", got, ok, want)
	}
	// A truncated file is a miss, not a wrong answer.
	if err := os.WriteFile(path, []byte{3, 0, 0, 0, 0, 0, 0, 0, 1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadUint64s(path); ok {
		t.Error("damaged cache file accepted")
	}
}

// A changed file gets a different key, so an older result is never read.
func TestAnalysisCacheKeyFollowsFile(t *testing.T) {
	if analysisCacheDir() == "" {
		t.Skip("analysis cache disabled")
	}
	f := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(f, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	k1 := analysisCachePath("sweep", fileIdentity(f), "0")
	if err := os.Chtimes(f, time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	k2 := analysisCachePath("sweep", fileIdentity(f), "0")
	if k1 == "" || k1 == k2 {
		t.Errorf("key did not change with the file: %q %q", k1, k2)
	}
	if analysisCachePath("sweep", fileIdentity(filepath.Join(t.TempDir(), "missing")), "0") != "" {
		t.Error("a file that cannot be identified must not be cached")
	}
}
