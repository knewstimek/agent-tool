package write

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteEmptyFileHonorsEncoding(t *testing.T) {
	for _, tt := range []struct {
		charset, text string
		want          []byte
	}{
		{"GB2312", "\u4e2d\u6587\r\n", []byte{0xd6, 0xd0, 0xce, 0xc4, '\r', '\n'}},
		{"GB-18030", "\u4e2d\u6587\r\n", []byte{0xd6, 0xd0, 0xce, 0xc4, '\r', '\n'}},
		{"EUC-KR", "\uac00\r\n", []byte{0xb0, 0xa1, '\r', '\n'}},
		{"UTF-16LE", "a\r\n", []byte{'a', 0, '\r', 0, '\n', 0}},
		{"GBK", "\U0001f600", nil},
		{"GB2312", "\U0001f600", nil},
		{"invalid-charset", "new", nil},
	} {
		for _, hintSource := range []string{"override", "editorconfig"} {
			t.Run(tt.charset+"/"+hintSource, func(t *testing.T) {
				d := t.TempDir()
				p := filepath.Join(d, "empty.txt")
				if err := os.WriteFile(p, nil, 0600); err != nil {
					t.Fatal(err)
				}
				input := WriteInput{FilePath: p, Content: tt.text}
				if hintSource == "override" {
					input.Encoding = tt.charset
				} else if err := os.WriteFile(filepath.Join(d, ".editorconfig"), []byte("root=true\n[*]\ncharset="+tt.charset+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				r, _, err := Handle(context.Background(), nil, input)
				if err != nil || r.IsError != (tt.want == nil) {
					t.Fatalf("unexpected write result: err=%v result=%+v", err, r)
				}
				got, err := os.ReadFile(p)
				if err != nil || !bytes.Equal(got, tt.want) {
					t.Fatalf("wrong bytes: got=%x want=%x err=%v", got, tt.want, err)
				}
			})
		}
	}
}
