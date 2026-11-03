package common

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRejectLossyDecoding(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		hint string
	}{
		{"utf16le high surrogate", []byte{0xff, 0xfe, 0x00, 0xd8}, ""},
		{"utf16be low surrogate", []byte{0xfe, 0xff, 0xdc, 0x00}, ""},
		{"utf16le odd byte", []byte{0xff, 0xfe, 0x41, 0x00, 0x42}, ""},
		{"utf16le hint", []byte{0x00, 0xd8}, "utf-16le"},
		{"utf16be hint", []byte{0xd8, 0x00}, "utf-16be"},
		{"utf8 BOM invalid", []byte{0xef, 0xbb, 0xbf, 0xff}, ""},
		{"utf8 hint invalid", []byte{0xff}, "utf-8"},
		{"euckr truncated", []byte{0xb0}, "euc-kr"},
		{"unknown hint", []byte("abc"), "invalid-charset"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "text")
			if err := os.WriteFile(p, tt.raw, 0600); err != nil {
				t.Fatal(err)
			}
			got, _, err := ReadFileWithEncoding(p, tt.hint)
			if err == nil || got != "" {
				t.Fatalf("accepted malformed bytes: %q, %v", got, err)
			}
			after, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(after, tt.raw) {
				t.Fatal("read changed original file")
			}
		})
	}
}

func TestUTF16ReplacementAndSupplementaryRoundTrip(t *testing.T) {
	for _, little := range []bool{true, false} {
		raw := []byte{0xfe, 0xff, 0xff, 0xfd, 0xd8, 0x3d, 0xde, 0x00}
		if little {
			raw = []byte{0xff, 0xfe, 0xfd, 0xff, 0x3d, 0xd8, 0x00, 0xde}
		}
		p := filepath.Join(t.TempDir(), "valid")
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
		got, info, err := ReadFileWithEncoding(p, "")
		if err != nil || got != "\ufffd\U0001f600" {
			t.Fatalf("valid UTF-16 rejected: %q %v", got, err)
		}
		if err := WriteFileWithEncoding(p, got, info); err != nil {
			t.Fatal(err)
		}
		after, _ := os.ReadFile(p)
		if !bytes.Equal(raw, after) {
			t.Fatalf("valid UTF-16 changed: %x -> %x", raw, after)
		}
	}
}

func TestInvalidEncodingWritePreservesOriginal(t *testing.T) {
	for _, tt := range []struct{ text, charset string }{
		{"new", "invalid-charset"},
		{string([]byte{0xff}), "utf-8"},
	} {
		p := filepath.Join(t.TempDir(), "text")
		if err := os.WriteFile(p, []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := WriteFileWithEncoding(p, tt.text, EncodingInfo{Charset: tt.charset}); err == nil {
			t.Fatal("expected write error")
		}
		after, _ := os.ReadFile(p)
		if string(after) != "original" {
			t.Fatal("invalid write changed original")
		}
	}
}
