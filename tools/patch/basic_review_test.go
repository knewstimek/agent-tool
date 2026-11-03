package patch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMalformedHunkDoesNotModifyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(p, []byte("a\nb\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, _, err := Handle(context.Background(), nil, PatchInput{FilePath: p, Patch: "@@ -1,2 +1,2 @@\n-a\n+A\n"})
	if err != nil || !r.IsError {
		t.Fatal("malformed hunk accepted")
	}
	got, _ := os.ReadFile(p)
	if string(got) != "a\nb\n" {
		t.Fatal("malformed hunk modified file")
	}
}

func TestZeroContextInsertionPositions(t *testing.T) {
	for _, tt := range []struct{ original, diff, want string }{
		{"", "@@ -0,0 +1 @@\n+new\n", "new\n"},
		{"a\nb\n", "@@ -1,0 +2 @@\n+middle\n", "a\nmiddle\nb\n"},
		{"a\nb\n", "@@ -2,0 +3 @@\n+last\n", "a\nb\nlast\n"},
	} {
		if got := apply(t, tt.original, tt.diff); got != tt.want {
			t.Fatalf("got=%q want=%q", got, tt.want)
		}
	}
}
func TestPatchCRAndHeaderLikeContent(t *testing.T) {
	for _, tt := range []struct{ original, diff, want string }{
		{"a\rb\rc\r", "@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n", "a\rB\rc\r"},
		{"--old\n", "@@ -1 +1 @@\n---old\n+++new\n", "++new\n"},
	} {
		if got := apply(t, tt.original, tt.diff); got != tt.want {
			t.Fatalf("got=%q want=%q", got, tt.want)
		}
	}
}
