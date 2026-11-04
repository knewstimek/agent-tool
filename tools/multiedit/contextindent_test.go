package multiedit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/text/encoding/korean"
)

func TestContextIndentLegacyBatchSaveAndPreview(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.cpp")
	content := "// 한글 주석\r\n" + strings.Repeat("void other() {\r\n    work();\r\n}\r\n", 40) +
		"void local() {\r\n  if (ready) {\r\n    target();\r\n  }\r\n}\r\n"
	raw, err := korean.EUCKR.NewEncoder().Bytes([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	input := MultiEditInput{FilePath: path, Encoding: "CP949", Edits: []EditOp{
		{OldString: "\ttarget();", NewString: "\tif (fresh) {\n\t\tadded();\n\t}"},
		{OldString: "\t\tadded();", NewString: "\t\tfinished();"},
	}}
	input.DryRun = true
	result, _, err := Handle(context.Background(), nil, input)
	if err != nil || result.IsError {
		t.Fatalf("preview: %v %+v", err, result)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("preview changed source")
	}
	input.DryRun = false
	result, _, err = Handle(context.Background(), nil, input)
	if err != nil || result.IsError {
		t.Fatalf("save: %v %+v", err, result)
	}
	wantText := strings.Replace(content, "    target();", "    if (fresh) {\r\n      finished();\r\n    }", 1)
	want, err := korean.EUCKR.NewEncoder().Bytes([]byte(wantText))
	if err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("saved bytes differ: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("unexpected backup/temp files: %v %v", entries, err)
	}
}
