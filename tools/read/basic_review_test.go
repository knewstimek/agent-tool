package read

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-tool/tools/fileinfo"
	"agent-tool/tools/multiread"
)

func TestReadLineBoundaryConsistency(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		t.Run(fmt.Sprintf("%x", ending), func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "lines.txt")
			if err := os.WriteFile(p, []byte("one"+ending+"two"+ending+"three"+ending), 0600); err != nil {
				t.Fatal(err)
			}
			limit := 1
			r, out, err := Handle(context.Background(), nil, ReadInput{FilePath: p, Offset: 2, Limit: &limit})
			if err != nil || r.IsError || out.TotalLines != 3 || out.ReturnedLines != 1 || out.NextOffset != 3 || !strings.Contains(out.Content, "2\ttwo\n") {
				t.Fatalf("read: %v %+v", err, out)
			}
			r, mout, err := multiread.Handle(context.Background(), nil, multiread.MultiReadInput{FilePaths: []string{p}, Offset: intPtr(2), Limit: &limit})
			if err != nil || r.IsError || !strings.Contains(mout.Content, "lines=2-2/3") || !strings.Contains(mout.Content, "2\ttwo\n") {
				t.Fatalf("multiread: %v %+v", err, mout)
			}
			r, fout, err := fileinfo.Handle(context.Background(), nil, fileinfo.FileInfoInput{FilePath: p})
			if err != nil || r.IsError || !strings.Contains(fout.Result, "Total lines: 3") {
				t.Fatalf("file_info: %v %+v", err, fout)
			}
		})
	}
}

func intPtr(n int) *int { return &n }

func TestReadBeyondEOFFinishes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "short.txt")
	if err := os.WriteFile(p, []byte("one\ntwo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, out, err := Handle(context.Background(), nil, ReadInput{FilePath: p, Offset: 3})
	if err != nil || r.IsError || out.ReturnedLines != 0 || out.NextOffset != 0 || strings.Contains(out.Content, "\ttwo\n") {
		t.Fatalf("repeated final line: %v %+v", err, out)
	}
	r, mout, err := multiread.Handle(context.Background(), nil, multiread.MultiReadInput{FilePaths: []string{p}, Offset: intPtr(3)})
	if err != nil || r.IsError || strings.Contains(mout.Content, "\ttwo\n") {
		t.Fatalf("multiread repeated final line: %v %+v", err, mout)
	}
}

func TestReadOffsetWithEndLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "range.txt")
	if err := os.WriteFile(p, []byte("one\ntwo\nthree\nfour\nfive\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, out, err := Handle(context.Background(), nil, ReadInput{FilePath: p, Offset: 3, EndLine: intPtr(4)})
	if err != nil || r.IsError || out.ReturnedLines != 2 || strings.Contains(out.Content, "\tfive\n") {
		t.Fatalf("end_line ignored offset: %v %+v", err, out)
	}
}

func TestReadRejectsFractionalOffset(t *testing.T) {
	p := filepath.Join(t.TempDir(), "range.txt")
	if err := os.WriteFile(p, []byte("one\ntwo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []any{1.5, []any{1.0, 2.5}} {
		r, _, err := Handle(context.Background(), nil, ReadInput{FilePath: p, Offset: offset})
		if err != nil || !r.IsError {
			t.Fatalf("fractional line silently rounded: %v %+v", offset, r)
		}
	}
}

func TestReadTightBudgetMakesProgress(t *testing.T) {
	p := filepath.Join(t.TempDir(), "long.txt")
	if err := os.WriteFile(p, []byte(strings.Repeat("x", 700)+"\ntail\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, out, err := Handle(context.Background(), nil, ReadInput{FilePath: p, MaxOutputChars: 256})
	if err != nil || r.IsError || out.ReturnedLines == 0 || out.NextOffset == 1 {
		t.Fatalf("read makes no progress: %v %+v", err, out)
	}
	r, mout, err := multiread.Handle(context.Background(), nil, multiread.MultiReadInput{FilePaths: []string{p}, MaxOutputChars: 1024})
	if err != nil || r.IsError || !strings.Contains(mout.Content, "1\t") || mout.NextOffset == 1 {
		t.Fatalf("multiread makes no progress: %v %+v", err, mout)
	}
}
