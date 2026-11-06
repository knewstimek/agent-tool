package codegraph

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Every pooled connection must carry the pragmas. A PRAGMA issued through
// db.Exec only reaches one connection, so concurrent queries (more likely now
// that long calls yield) silently ran without foreign keys or busy_timeout.
func TestOpenDBAppliesPragmasToEveryConnection(t *testing.T) {
	db, err := openDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		conn, err := db.Conn(ctx) // held open so each iteration gets a new connection
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		var fk, busy int
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy); err != nil {
			t.Fatal(err)
		}
		if fk != 1 || busy != 10000 {
			t.Fatalf("connection %d: foreign_keys=%d busy_timeout=%d", i, fk, busy)
		}
	}
}

func writeGoFile(t *testing.T, root, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte("package p\nfunc F() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCancelledIndexKeepsDataAndSkipsPurge(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, "a.go")
	if _, err := opIndex(context.Background(), CodeGraphInput{Path: root, Workers: 1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := opIndex(ctx, CodeGraphInput{Path: root, Workers: 1})
	if err != nil || !strings.Contains(result, "Index cancelled") || !strings.Contains(result, "0 removed") {
		t.Fatalf("cancelled index: result=%q err=%v", result, err)
	}
	db, err := openDB(root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var files int
	if err := db.QueryRow("SELECT COUNT(*) FROM files").Scan(&files); err != nil || files != 1 {
		t.Fatalf("cancelled walk purged indexed files: count=%d err=%v", files, err)
	}
}

func TestConcurrentIndexOfSameRootIsRefused(t *testing.T) {
	root := t.TempDir()
	writeGoFile(t, root, "a.go")
	value, _ := indexLocks.LoadOrStore(strings.ToLower(filepath.Clean(root)), &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock() // simulate an index already running on this root
	defer lock.Unlock()
	_, err := opIndex(context.Background(), CodeGraphInput{Path: root, Workers: 1})
	if err == nil || !strings.Contains(err.Error(), "already running") || !strings.Contains(err.Error(), "job_action") {
		t.Fatalf("second index was not refused with guidance: %v", err)
	}
}
