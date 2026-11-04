package diff

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func contextPtr(n int) *int { return &n }

func TestDiffOnlyFinalNewlineVersusMixedPlacement(t *testing.T) {
	for _, tt := range []struct {
		a, b       string
		endingDiff bool
	}{
		{"a\nb", "a\nb\n", false},
		{"a\r\nb\n", "a\nb\r\n", true},
	} {
		d := t.TempDir()
		a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
		if err := os.WriteFile(a, []byte(tt.a), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(b, []byte(tt.b), 0600); err != nil {
			t.Fatal(err)
		}
		r, out, err := Handle(context.Background(), nil, DiffInput{FileA: a, FileB: b})
		if err != nil || r.IsError || strings.Contains(out.Result, "line endings differ") != tt.endingDiff {
			t.Fatalf("wrong newline report: %v %+v", err, out)
		}
	}
}
func TestDiffAcceptsZeroContextAndIdenticalLargeFiles(t *testing.T) {
	d := t.TempDir()
	a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
	if err := os.WriteFile(a, []byte("one\nold\nthree\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("one\nnew\nthree\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, out, err := Handle(context.Background(), nil, DiffInput{FileA: a, FileB: b, ContextLines: contextPtr(0)})
	if err != nil || r.IsError || strings.Contains(out.Result, " one\n") || !strings.Contains(out.Result, "@@ -2,1 +2,1 @@") {
		t.Fatalf("zero context ignored: %v %+v", err, out)
	}
	large := []byte(strings.Repeat("same\n", 50001))
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, large, 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, out, err = Handle(context.Background(), nil, DiffInput{FileA: a, FileB: b})
	if err != nil || r.IsError || out.Result != "Files are identical" {
		t.Fatalf("identical files need no line diff: %v %+v", err, out)
	}
}

func TestPerFileEncodingOverrides(t *testing.T) {
	d := t.TempDir()
	a, b := filepath.Join(d, "utf8.txt"), filepath.Join(d, "legacy.txt")
	if err := os.WriteFile(a, []byte("\uac00"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte{0xb0, 0xa1}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, ".editorconfig"), []byte("root=true\n[*]\ncharset=utf-8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, out, err := Handle(context.Background(), nil, DiffInput{FileA: a, FileB: b, EncodingA: "UTF-8", EncodingB: "CP949"})
	if err != nil || r.IsError || !strings.Contains(out.Result, "Decoded text is identical") {
		t.Fatalf("per-file encodings: %v %+v", err, out)
	}
}

func TestCRDiffIsLineEndingOnly(t *testing.T) {
	d := t.TempDir()
	a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
	for p, data := range map[string]string{a: "one\rtwo\r", b: "one\ntwo\n"} {
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, out, err := Handle(context.Background(), nil, DiffInput{FileA: a, FileB: b})
	if err != nil || r.IsError || strings.Contains(out.Result, "@@") || !strings.Contains(out.Result, "line endings differ") {
		t.Fatalf("CR treated as content: %v %+v", err, out)
	}
}
func TestIdenticalTextReportsDifferentEncoding(t *testing.T) {
	d := t.TempDir()
	a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
	if err := os.WriteFile(a, []byte("same"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte{0xff, 0xfe, 's', 0, 'a', 0, 'm', 0, 'e', 0}, 0600); err != nil {
		t.Fatal(err)
	}
	r, out, err := Handle(context.Background(), nil, DiffInput{FileA: a, FileB: b})
	if err != nil || r.IsError || out.Result == "Files are identical" || !strings.Contains(out.Result, "encoding") {
		t.Fatalf("different bytes called identical: %v %+v", err, out)
	}
}
