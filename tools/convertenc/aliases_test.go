package convertenc

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestChineseTargetAliases(t *testing.T) {
	for _, tt := range []struct{ target, charset, text string }{
		{"GB18030", "GB18030", "\u4e2d\u6587\U0001f600\r\n"},
		{" GB-18030 ", "GB18030", "\u4e2d\u6587\U0001f600\r\n"},
		{"GBK", "GBK", "\u4e2d\u6587\r\n"},
		{"GB2312", "GBK", "\u4e2d\u6587\r\n"},
	} {
		t.Run(tt.target, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "source.txt")
			if err := os.WriteFile(p, []byte(tt.text), 0600); err != nil {
				t.Fatal(err)
			}
			r, out, err := Handle(context.Background(), nil, ConvertInput{FilePath: p, ToEncoding: tt.target})
			if err != nil || r.IsError || !strings.Contains(out.Result, "UTF-8 \u2192 "+tt.charset) {
				t.Fatalf("target conversion failed: err=%v result=%+v output=%+v", err, r, out)
			}
			codec := simplifiedchinese.GBK
			if tt.charset == "GB18030" {
				codec = simplifiedchinese.GB18030
			}
			want, err := codec.NewEncoder().Bytes([]byte(tt.text))
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("wrong target bytes: got=%x want=%x err=%v", got, want, err)
			}
			r, _, err = Handle(context.Background(), nil, ConvertInput{FilePath: p, FromEncoding: tt.target, ToEncoding: "UTF-8"})
			if err != nil || r.IsError {
				t.Fatalf("source alias conversion failed: err=%v result=%+v", err, r)
			}
			got, err = os.ReadFile(p)
			if err != nil || string(got) != tt.text {
				t.Fatalf("round trip failed: got=%x err=%v", got, err)
			}
		})
	}
}
