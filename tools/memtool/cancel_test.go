package memtool

import (
	"context"
	"errors"
	"testing"
)

// zeroMem exposes one large readable region of zeros and counts reads. It
// cancels ctx on the first read to simulate job_action=cancel mid-scan.
type zeroMem struct {
	reads  int
	cancel context.CancelFunc
}

func (z *zeroMem) Open(int, bool, bool) error { return nil }
func (z *zeroMem) Close()                     {}
func (z *zeroMem) Regions() ([]MemoryRegion, error) {
	return []MemoryRegion{{BaseAddress: 0x10000, Size: 256 * 1024 * 1024, Protection: "rw-"}}, nil
}
func (z *zeroMem) ReadMemory(_ uint64, buf []byte) (int, error) {
	z.reads++
	if z.cancel != nil {
		z.cancel()
	}
	return len(buf), nil
}
func (z *zeroMem) WriteMemory(_ uint64, d []byte) (int, error) { return len(d), nil }

func cancelledMidScan(t *testing.T) (ProcessReader, *zeroMem) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mem := &zeroMem{cancel: cancel}
	return withCtx(ctx, mem), mem
}

func TestScansStopOnCancel(t *testing.T) {
	// 256 MiB / 4 MiB chunks = 64 reads if cancellation were ignored.
	scans := map[string]func(ProcessReader) error{
		"search": func(r ProcessReader) error {
			_, err := searchMemory(r, []byte{1, 2, 3, 4}, TypeInt32, 4, "")
			return err
		},
		"struct_search": func(r ProcessReader) error {
			_, err := structSearch(r, []structField{{Offset: 0, encoded: []byte{1, 2, 3, 4}}}, 4, "")
			return err
		},
		"pointer_scan": func(r ProcessReader) error {
			_, err := pointerScan(r, 0x10000, 1, 0x100, 8, "")
			return err
		},
		"snapshot": func(r ProcessReader) error {
			snap, _, err := takeSnapshot(r, "")
			if snap != nil {
				snap.Close()
			}
			return err
		},
	}
	for name, scan := range scans {
		t.Run(name, func(t *testing.T) {
			r, mem := cancelledMidScan(t)
			err := scan(r)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation error, got %v", err)
			}
			if mem.reads > 2 {
				t.Fatalf("scan kept reading after cancel: %d reads", mem.reads)
			}
		})
	}
}

// A cancelled filter must error (so opFilter rolls back) rather than return a
// truncated store that would replace the session's matches.
func TestFilterErrorsOnCancel(t *testing.T) {
	store := newMatchStore(4)
	for i := 0; i < 3; i++ {
		if err := store.Add(scanMatch{Address: 0x10000 + uint64(i)*4, PrevData: make([]byte, 4)}); err != nil {
			t.Fatal(err)
		}
	}
	defer store.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	session := &scanSession{valueType: TypeInt32, valueSize: 4, store: store}
	if _, err := filterMatches(withCtx(ctx, &zeroMem{}), session, "unchanged", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("filter returned %v, want cancellation", err)
	}
}

func TestPlainReaderIsNeverCancelled(t *testing.T) {
	if err := cancelled(&zeroMem{}); err != nil {
		t.Fatalf("plain reader reported %v", err)
	}
}
