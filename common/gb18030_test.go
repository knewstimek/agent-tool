package common

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestGB18030ReadEditRoundTrip(t *testing.T) {
	original := strings.Repeat("/* \u5185\u5b58\u5757\u6a21\u5f0f \u4e2d\u6587\u6d4b\u8bd5 \u6570\u636e\u5904\u7406 */\r\n", 100)
	raw, err := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte(original))
	if err != nil {
		t.Fatal(err)
	}
	for _, hint := range []string{"", "GB-18030", "gb18030", "  Gb-18030  "} {
		t.Run("hint="+hint, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "source.c")
			if err := os.WriteFile(p, raw, 0600); err != nil {
				t.Fatal(err)
			}
			got, info, err := ReadFileWithEncodingHash(p, hint)
			if err != nil || got != original || info.Charset != "GB18030" {
				t.Fatalf("GB18030 read failed: charset=%s source=%s err=%v text_matches=%t", info.Charset, info.UsedSource, err, got == original)
			}
			if hint == "" && info.UsedSource != "chardet" {
				t.Fatalf("auto-detection not exercised: %+v", info)
			}
			// A supplementary character exercises GB18030's four-byte encoding.
			edited := strings.Replace(got, "/* ", "/* \U0001f600 ", 1)
			if err := WriteFileWithEncoding(p, edited, info); err != nil {
				t.Fatal(err)
			}
			want, err := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte(edited))
			if err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(after, want) {
				t.Fatalf("edited bytes or CRLF changed: err=%v", err)
			}
			reopened, reopenedInfo, err := ReadFileWithEncoding(p, "")
			if err != nil || reopened != edited || reopenedInfo.Charset != "GB18030" {
				t.Fatalf("edited GB18030 could not be reopened: charset=%s err=%v", reopenedInfo.Charset, err)
			}
		})
	}
}
