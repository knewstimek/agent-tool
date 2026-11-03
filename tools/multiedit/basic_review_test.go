package multiedit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-tool/common"
)

func TestBatchGuardAndFailureAtomicity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "text.txt")
	original := "\talpha\n\tbeta\n"
	if err := os.WriteFile(p, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	r, _, err := Handle(context.Background(), nil, MultiEditInput{FilePath: p, ExpectedHash: strings.Repeat("0", 64), Edits: []EditOp{{OldString: "alpha", NewString: "changed"}}})
	if err != nil || !r.IsError {
		t.Fatal("stale hash accepted")
	}
	hash, err := common.ComputeFileHash(p)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err = Handle(context.Background(), nil, MultiEditInput{FilePath: p, ExpectedHash: hash, Edits: []EditOp{{OldString: "alpha", NewString: "changed"}, {OldString: "missing", NewString: "new"}}})
	if err != nil || !r.IsError {
		t.Fatal("failed batch accepted")
	}
	got, _ := os.ReadFile(p)
	if string(got) != original {
		t.Fatal("partial batch was written")
	}
	r, _, err = Handle(context.Background(), nil, MultiEditInput{FilePath: p, ExpectedHash: hash, IndentStyle: "tabs", Edits: []EditOp{{OldString: "\talpha", NewString: "    changed"}}})
	if err != nil || r.IsError {
		t.Fatalf("valid guarded batch failed: %v %+v", err, r)
	}
	got, _ = os.ReadFile(p)
	if string(got) != "\tchanged\n\tbeta\n" {
		t.Fatalf("forced style not applied: %q", got)
	}
}
