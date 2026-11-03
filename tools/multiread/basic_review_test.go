package multiread

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMixedPerFileEncodingAndCapturedHashes(t *testing.T) {
	d := t.TempDir()
	kr, jp := filepath.Join(d, "kr.txt"), filepath.Join(d, "jp.txt")
	a, b := []byte{0xb0, 0xa1, '\n'}, []byte{0x82, 0xa0, '\n'}
	for p, raw := range map[string][]byte{kr: a, jp: b} {
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(d, ".editorconfig"), []byte("root=true\n[*]\ncharset=utf-8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, out, err := Handle(context.Background(), nil, MultiReadInput{Encoding: "CP949", IncludeHash: true, Files: []FileRange{{Path: kr}, {Path: jp, Encoding: "Shift_JIS"}}})
	if err != nil || r.IsError || out.FilesRead != 2 || out.ErrorCount != 0 {
		t.Fatalf("mixed encoding: %v %+v", err, out)
	}
	for _, text := range []string{"\uac00", "\u3042", fmt.Sprintf("%x", sha256.Sum256(a)), fmt.Sprintf("%x", sha256.Sum256(b))} {
		if !strings.Contains(out.Content, text) {
			t.Fatalf("missing %q: %s", text, out.Content)
		}
	}
}

func TestTightBudgetCursorContinuesWithoutDuplicates(t *testing.T) {
	d := t.TempDir()
	var paths []string
	for i := 0; i < 3; i++ {
		p := filepath.Join(d, fmt.Sprintf("%d.txt", i))
		if err := os.WriteFile(p, []byte(fmt.Sprintf("unique-%d\n", i)+strings.Repeat("x", 200)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	seen := map[string]int{}
	index, offset := 0, 1
	for page := 0; page < 20; page++ {
		r, out, err := Handle(context.Background(), nil, MultiReadInput{FilePaths: paths[index:], Offset: &offset, MaxOutputChars: 512})
		if err != nil || r.IsError {
			t.Fatalf("page: %v %+v", err, out)
		}
		for i := 0; i < 3; i++ {
			key := fmt.Sprintf("unique-%d", i)
			seen[key] += strings.Count(out.Content, key)
		}
		if out.NextFileIndex == 0 {
			break
		}
		next := index + out.NextFileIndex - 1
		nextOffset := out.NextOffset
		if nextOffset == 0 {
			nextOffset = 1
		}
		if next == index && nextOffset == offset {
			t.Fatalf("cursor stuck: %+v", out)
		}
		index, offset = next, nextOffset
		if page == 19 {
			t.Fatal("pagination did not finish")
		}
	}
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("unique-%d", i)
		if seen[key] != 1 {
			t.Fatalf("%s appeared %d times", key, seen[key])
		}
	}
}

func TestErrorEntryIsNotLostWhenBudgetRunsOut(t *testing.T) {
	d := t.TempDir()
	paths := []string{filepath.Join(d, strings.Repeat("a", 100)), filepath.Join(d, "also-missing")}
	r, out, err := Handle(context.Background(), nil, MultiReadInput{FilePaths: paths, MaxOutputChars: 256})
	if err != nil || r.IsError {
		t.Fatalf("per-file errors should be returned: %v %+v", err, out)
	}
	if out.NextFileIndex == 0 && !strings.Contains(out.Content, "ERROR:") {
		t.Fatalf("lost errors without continuation: %+v", out)
	}
}
