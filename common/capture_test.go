package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBoundedCaptureKeepsHeadTailAndCountsOriginal(t *testing.T) {
	c := NewBoundedCapture(10)
	input := "abcde" + strings.Repeat("x", 20) + "vwxyz"
	n, err := c.Write([]byte(input))
	if err != nil || n != len(input) {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	got, total, truncated := c.Result()
	if !truncated || total != int64(len(input)) {
		t.Fatalf("metadata = total %d, truncated %v", total, truncated)
	}
	if !strings.Contains(got, "abcde") || !strings.Contains(got, "vwxyz") || !strings.Contains(got, "original_bytes=30") {
		t.Fatalf("unexpected capture: %q", got)
	}
}

func TestFileCaptureMatchesBoundedCapture(t *testing.T) {
	input := "abcde" + strings.Repeat("x", 20) + "vwxyz"
	path := filepath.Join(t.TempDir(), "log")
	for _, content := range []string{input, "short"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		mem := NewBoundedCapture(10)
		_, _ = mem.Write([]byte(content))
		wantText, wantTotal, wantTrunc := mem.Result()
		gotText, gotTotal, gotTrunc := NewFileCapture(path, 10).Result()
		if gotText != wantText || gotTotal != wantTotal || gotTrunc != wantTrunc {
			t.Fatalf("file %q/%d/%v != memory %q/%d/%v", gotText, gotTotal, gotTrunc, wantText, wantTotal, wantTrunc)
		}
	}
	if text, total, _ := NewFileCapture(filepath.Join(t.TempDir(), "missing"), 10).Result(); text != "" || total != 0 {
		t.Fatalf("missing file should read as empty, got %q/%d", text, total)
	}
}

func TestBoundedCaptureReturnsValidUTF8AtSplitBoundaries(t *testing.T) {
	c := NewBoundedCapture(7)
	_, _ = c.Write([]byte(strings.Repeat("한", 20)))
	got, _, _ := c.Result()
	if !utf8.ValidString(got) {
		t.Fatalf("invalid UTF-8: %q", got)
	}
}

func TestBoundedCaptureModes(t *testing.T) {
	for _, tc := range []struct {
		mode, want, absent string
	}{
		{"head", "abcde", "vwxyz"},
		{"tail", "vwxyz", "abcde"},
	} {
		c := NewBoundedCaptureMode(5, tc.mode)
		_, _ = c.Write([]byte("abcde---vwxyz"))
		got, _, truncated := c.Result()
		if !truncated || !strings.Contains(got, tc.want) || strings.Contains(got, tc.absent) {
			t.Fatalf("mode %s: %q", tc.mode, got)
		}
	}
}
