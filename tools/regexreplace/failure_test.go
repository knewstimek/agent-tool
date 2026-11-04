package regexreplace

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func resultText(r *mcp.CallToolResult) string {
	var s strings.Builder
	for _, c := range r.Content {
		if text, ok := c.(*mcp.TextContent); ok {
			s.WriteString(text.Text)
		}
	}
	return s.String()
}

func TestReplacementCaptureAndEmptyMatchSemantics(t *testing.T) {
	for _, tt := range []struct {
		source, pattern, replacement, want string
		count                              int
	}{
		{"baac a\n", "\\B(a)", "<$1>", "b<a><a>c a\n", 2},
		{"ab", "^|$", "x", "xabx", 2},
		{"a a", "(?P<v>a)", "${v}${v}", "aa aa", 2},
	} {
		p := filepath.Join(t.TempDir(), "source.txt")
		if err := os.WriteFile(p, []byte(tt.source), 0600); err != nil {
			t.Fatal(err)
		}
		r, out, err := Handle(context.Background(), nil, RegexReplaceInput{Path: p, Pattern: tt.pattern, Replacement: tt.replacement})
		got, _ := os.ReadFile(p)
		if err != nil || r.IsError || out.TotalReplacements != tt.count || string(got) != tt.want {
			t.Fatalf("pattern=%q got=%q want=%q count=%d err=%v", tt.pattern, got, tt.want, out.TotalReplacements, err)
		}
	}
}
func TestDenseDryRunDoesNotCollectAllMatchIndices(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dense.txt")
	if err := os.WriteFile(p, []byte(strings.Repeat("a", 512*1024)), 0600); err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile("a")
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	result, err := processFile(p, re, "b", true, &scanStats{}, "")
	runtime.ReadMemStats(&after)
	if err != nil || result == nil || result.count != 512*1024 {
		t.Fatalf("dense dry run: %v %+v", err, result)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16*1024*1024 {
		t.Fatalf("dense dry run allocated %d bytes", allocated)
	}
}
func TestDirectoryReportsAllFailuresAndExplicitHiddenRoot(t *testing.T) {
	d := filepath.Join(t.TempDir(), ".explicit")
	if err := os.Mkdir(d, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "bad.txt")
	if err := os.WriteFile(p, []byte{0xef, 0xbb, 0xbf, 0xff}, 0600); err != nil {
		t.Fatal(err)
	}
	r, out, err := Handle(context.Background(), nil, RegexReplaceInput{Path: d, Pattern: "target", Replacement: "done"})
	if err != nil || !r.IsError || out.ErrorCount != 1 || strings.Contains(resultText(r), "No matches found") {
		t.Fatalf("failed scan reported as no match: %v %+v %s", err, out, resultText(r))
	}
}

func TestInvalidGlobDoesNotWriteAndErrorSamplesAreBounded(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "good.txt")
	if err := os.WriteFile(p, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	r, _, err := Handle(context.Background(), nil, RegexReplaceInput{Path: d, Glob: "[", Pattern: "target", Replacement: "done"})
	if err != nil || !r.IsError {
		t.Fatal("invalid glob was silently accepted")
	}
	raw, _ := os.ReadFile(p)
	if string(raw) != "target" {
		t.Fatal("invalid request changed a file")
	}
	for i := 0; i < 12; i++ {
		if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("bad-%02d.txt", i)), []byte{0xef, 0xbb, 0xbf, 0xff}, 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, out, err := Handle(context.Background(), nil, RegexReplaceInput{Path: d, Pattern: "target", Replacement: "done"})
	if err != nil || out.ErrorCount != 12 || !out.Truncated || strings.Count(resultText(r), "ERROR:") != 8 {
		t.Fatalf("error sample not bounded or counted: %v %+v %s", err, out, resultText(r))
	}
}

func TestDirectoryReportsPartialFailures(t *testing.T) {
	d := t.TempDir()
	good, bad := filepath.Join(d, "a-good.txt"), filepath.Join(d, "b-bad.txt")
	if err := os.WriteFile(good, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	raw := []byte{0xef, 0xbb, 0xbf, 0xff}
	if err := os.WriteFile(bad, raw, 0600); err != nil {
		t.Fatal(err)
	}
	r, out, err := Handle(context.Background(), nil, RegexReplaceInput{Path: d, Glob: "*.txt", Pattern: "target", Replacement: "done"})
	if err != nil {
		t.Fatal(err)
	}
	text := resultText(r)
	if out.FilesChanged != 1 || !strings.Contains(text, "ERROR") || !strings.Contains(text, "b-bad.txt") {
		t.Fatalf("partial result concealed: %+v %s", out, text)
	}
	got, _ := os.ReadFile(good)
	if string(got) != "done" {
		t.Fatal("successful file missing from partial result")
	}
	got, _ = os.ReadFile(bad)
	if string(got) != string(raw) {
		t.Fatal("failed file changed")
	}
}
func TestDirectoryReportsItsLimit(t *testing.T) {
	d := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(d, name), []byte("target"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, out, err := Handle(context.Background(), nil, RegexReplaceInput{Path: d, Pattern: "target", Replacement: "done", MaxFiles: 1})
	if err != nil || r.IsError || out.FilesChanged != 1 || !strings.Contains(resultText(r), "limit_reached=true") {
		t.Fatalf("limit concealed: %v %+v %s", err, out, resultText(r))
	}
}
