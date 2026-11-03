package read

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-tool/tools/edit"
	"agent-tool/tools/multiedit"
	"agent-tool/tools/write"
)

func TestEncodingOverrideRecovery(t *testing.T) {
	for _, tt := range []struct {
		name, encoding, text string
		raw                  []byte
	}{
		{"Korean", " EUC-KR ", "\uac00", []byte{0xb0, 0xa1}},
		{"CP949 extended Korean", "CP949", "\uac02", []byte{0x81, 0x41}},
		{"Japanese", "Shift_JIS", "\u3042", []byte{0x82, 0xa0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := t.TempDir()
			if err := os.WriteFile(filepath.Join(d, ".editorconfig"), []byte("root=true\n[*]\ncharset=utf-8\n"), 0600); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(d, "legacy.txt")
			if err := os.WriteFile(p, append(append([]byte{}, tt.raw...), 'A'), 0600); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			failed, _, err := Handle(ctx, nil, ReadInput{FilePath: p})
			if err != nil || !failed.IsError {
				t.Fatal("wrong charset should be reported")
			}
			r, out, err := Handle(ctx, nil, ReadInput{FilePath: p, Encoding: tt.encoding})
			if err != nil || r.IsError || !strings.Contains(out.Content, tt.text+"A") {
				t.Fatalf("explicit read: %v %+v %+v", err, r, out)
			}
			r, _, err = edit.Handle(ctx, nil, edit.EditInput{FilePath: p, Encoding: tt.encoding, OldString: "A", NewString: "B"})
			if err != nil || r.IsError {
				t.Fatalf("explicit edit: %v %+v", err, r)
			}
			got, _ := os.ReadFile(p)
			want := append(append([]byte{}, tt.raw...), 'B')
			if !bytes.Equal(got, want) {
				t.Fatalf("edit changed encoding: %x want %x", got, want)
			}
			r, _, err = multiedit.Handle(ctx, nil, multiedit.MultiEditInput{FilePath: p, Encoding: tt.encoding, Edits: []multiedit.EditOp{{OldString: "B", NewString: "D"}}})
			if err != nil || r.IsError {
				t.Fatalf("explicit multiedit: %v %+v", err, r)
			}
			got, _ = os.ReadFile(p)
			want[len(want)-1] = 'D'
			if !bytes.Equal(got, want) {
				t.Fatalf("multiedit changed encoding: %x want %x", got, want)
			}
			r, _, err = write.Handle(ctx, nil, write.WriteInput{FilePath: p, Encoding: tt.encoding, Content: tt.text + "C"})
			if err != nil || r.IsError {
				t.Fatalf("explicit overwrite: %v %+v", err, r)
			}
			got, _ = os.ReadFile(p)
			want[len(want)-1] = 'C'
			if !bytes.Equal(got, want) {
				t.Fatalf("write changed encoding: %x want %x", got, want)
			}
			np := filepath.Join(d, "new.txt")
			r, _, err = write.Handle(ctx, nil, write.WriteInput{FilePath: np, Encoding: tt.encoding, Content: tt.text + "C"})
			if err != nil || r.IsError {
				t.Fatalf("explicit creation: %v %+v", err, r)
			}
			got, _ = os.ReadFile(np)
			if !bytes.Equal(got, want) {
				t.Fatalf("new file encoding: %x want %x", got, want)
			}
		})
	}
}

func TestEncodingOverridePreservesExistingBOM(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bom.txt")
	raw := append([]byte{0xef, 0xbb, 0xbf}, []byte("\uac00A")...)
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	r, _, err := edit.Handle(context.Background(), nil, edit.EditInput{FilePath: p, Encoding: "EUC-KR", OldString: "A", NewString: "B"})
	if err != nil || r.IsError {
		t.Fatalf("BOM priority: %v %+v", err, r)
	}
	got, _ := os.ReadFile(p)
	raw[len(raw)-1] = 'B'
	if !bytes.Equal(got, raw) {
		t.Fatalf("BOM or original encoding changed: %x", got)
	}
}
