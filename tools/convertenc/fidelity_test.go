package convertenc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitSourceEncodingRoundTrip(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "legacy.txt")
	raw := []byte{0x81, 0x41, '\r', '\n'}
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, ".editorconfig"), []byte("root=true\n[*]\ncharset=utf-8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, _, err := Handle(context.Background(), nil, ConvertInput{FilePath: p, FromEncoding: "CP949", ToEncoding: "UTF-8-BOM"})
	if err != nil || r.IsError {
		t.Fatalf("explicit source failed: %v %+v", err, r)
	}
	got, _ := os.ReadFile(p)
	want := append([]byte{0xef, 0xbb, 0xbf}, []byte("\uac02\r\n")...)
	if string(got) != string(want) {
		t.Fatalf("UTF-8-BOM bytes=%x want=%x", got, want)
	}
	r, _, err = Handle(context.Background(), nil, ConvertInput{FilePath: p, ToEncoding: "CP949"})
	if err != nil || r.IsError {
		t.Fatalf("BOM source conversion failed: %v %+v", err, r)
	}
	got, _ = os.ReadFile(p)
	if string(got) != string(raw) {
		t.Fatalf("round trip changed bytes: %x", got)
	}
}

func TestGBKDoesNotSilentlyBecomeGB18030(t *testing.T) {
	p := filepath.Join(t.TempDir(), "source.txt")
	original := "\U0001f600"
	if err := os.WriteFile(p, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	r, _, err := Handle(context.Background(), nil, ConvertInput{FilePath: p, ToEncoding: "GBK"})
	if err != nil || !r.IsError {
		t.Fatalf("GBK silently accepted a GB18030-only character: %v %+v", err, r)
	}
	got, _ := os.ReadFile(p)
	if string(got) != original {
		t.Fatal("failed conversion changed source")
	}
}
