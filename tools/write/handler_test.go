package write

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteNewEditorConfigEncoding(t *testing.T) {
	tests := []struct {
		charset string
		want    []byte
	}{
		{"utf-8-bom", []byte{0xef, 0xbb, 0xbf, 'a', '\n'}},
		{"utf-8", []byte("a\n")},
		{"utf-16le", []byte{'a', 0, '\n', 0}},
		{"utf-16be", []byte{0, 'a', 0, '\n'}},
		{"euc-kr", []byte("a\n")},
	}
	for _, tt := range tests {
		t.Run(tt.charset, func(t *testing.T) {
			d := t.TempDir()
			if err := os.WriteFile(filepath.Join(d, ".editorconfig"), []byte("root=true\n[*]\ncharset="+tt.charset+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(d, "new.txt")
			r, _, err := Handle(context.Background(), nil, WriteInput{FilePath: p, Content: "a\n"})
			if err != nil || r.IsError {
				t.Fatalf("write failed: %v %+v", err, r)
			}
			got, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(got, tt.want) {
				t.Fatalf("got %x want %x err=%v", got, tt.want, err)
			}
		})
	}
}

func TestWriteRefusesUnreadableEncoding(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.txt")
	raw := []byte{0xff, 0xfe, 0x00, 0xd8}
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	r, _, err := Handle(context.Background(), nil, WriteInput{FilePath: p, Content: "new"})
	if err != nil || !r.IsError {
		t.Fatalf("expected tool error: %v %+v", err, r)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, raw) {
		t.Fatalf("original overwritten: %x", got)
	}
}
