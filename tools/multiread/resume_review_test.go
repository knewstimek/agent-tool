package multiread

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingFooterDoesNotExpandRequestedRange(t *testing.T) {
	d := t.TempDir()
	a, b := filepath.Join(d, "a.txt"), filepath.Join(d, "b.txt")
	if err := os.WriteFile(a, []byte(strings.Repeat("x", 1000)+"\nunrequested\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("next\n"), 0600); err != nil {
		t.Fatal(err)
	}
	limit := 1
	r, out, err := Handle(context.Background(), nil, MultiReadInput{FilePaths: []string{a, b}, Limit: &limit, MaxOutputChars: 512})
	if err != nil || r.IsError || out.NextFileIndex != 2 || out.NextOffset != 0 {
		t.Fatalf("requested range expanded: %v %+v", err, out)
	}
}

func TestResumeDoesNotSlideCurrentFileWindow(t *testing.T) {
	for _, tt := range []struct{ offset, limit, first, last int }{{2, 3, 2, 4}, {-3, 2, 6, 7}} {
		p := filepath.Join(t.TempDir(), "bounded.txt")
		var body strings.Builder
		for i := 1; i <= 8; i++ {
			fmt.Fprintf(&body, "row-%d %s\n", i, strings.Repeat("x", 80))
		}
		if err := os.WriteFile(p, []byte(body.String()), 0600); err != nil {
			t.Fatal(err)
		}
		input := MultiReadInput{FilePaths: []string{p}, Offset: &tt.offset, Limit: &tt.limit, MaxOutputChars: 512}
		seen := map[int]int{}
		for page := 0; page < 20; page++ {
			r, out, err := Handle(context.Background(), nil, input)
			if err != nil || r.IsError {
				t.Fatalf("bounded resume: %v %+v", err, out)
			}
			for i := 1; i <= 8; i++ {
				seen[i] += strings.Count(out.Content, fmt.Sprintf("\trow-%d ", i))
			}
			if out.NextFileIndex == 0 {
				break
			}
			input.StartFileIndex = out.NextFileIndex
			next := out.NextOffset
			input.ResumeOffset = &next
			if page == 19 {
				t.Fatal("bounded resume did not finish")
			}
		}
		for i := 1; i <= 8; i++ {
			want := 0
			if i >= tt.first && i <= tt.last {
				want = 1
			}
			if seen[i] != want {
				t.Fatalf("offset=%d limit=%d row=%d seen=%d want=%d", tt.offset, tt.limit, i, seen[i], want)
			}
		}
	}
}

func TestResumeOriginalListKeepsLaterFileRanges(t *testing.T) {
	d := t.TempDir()
	var paths []string
	for i := 0; i < 3; i++ {
		p := filepath.Join(d, fmt.Sprintf("file%d.txt", i))
		var content strings.Builder
		for line := 1; line <= 8; line++ {
			fmt.Fprintf(&content, "file%d-line%d %s\n", i, line, strings.Repeat("x", 40))
		}
		if err := os.WriteFile(p, []byte(content.String()), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	originalOffset := 2
	input := MultiReadInput{FilePaths: paths, Offset: &originalOffset, All: true, MaxOutputChars: 512}
	seen := map[string]int{}
	for page := 0; page < 50; page++ {
		r, out, err := Handle(context.Background(), nil, input)
		if err != nil || r.IsError {
			t.Fatalf("resume failed: %v %+v", err, out)
		}
		for file := 0; file < 3; file++ {
			for line := 1; line <= 8; line++ {
				key := fmt.Sprintf("file%d-line%d ", file, line)
				seen[key] += strings.Count(out.Content, key)
			}
		}
		if out.NextFileIndex == 0 {
			break
		}
		if input.StartFileIndex == out.NextFileIndex && input.ResumeOffset != nil && *input.ResumeOffset == out.NextOffset {
			t.Fatalf("stuck: %+v", out)
		}
		input.StartFileIndex = out.NextFileIndex
		if out.NextOffset > 0 {
			next := out.NextOffset
			input.ResumeOffset = &next
		} else {
			input.ResumeOffset = nil
		}
		if page == 49 {
			t.Fatal("pagination did not finish")
		}
	}
	for file := 0; file < 3; file++ {
		for line := 1; line <= 8; line++ {
			key := fmt.Sprintf("file%d-line%d ", file, line)
			want := 1
			if line == 1 {
				want = 0
			}
			if seen[key] != want {
				t.Fatalf("%s seen=%d want=%d", key, seen[key], want)
			}
		}
	}
}
