package grep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAllModesFindMatchAfterLongLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "long.txt")
	if err := os.WriteFile(p, []byte(strings.Repeat("x", 100000)+"\nneedle\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"content", "count", "files_with_matches"} {
		r, out, err := Handle(context.Background(), nil, GrepInput{Path: p, Pattern: "^needle$", OutputMode: mode})
		if err != nil || r.IsError || out.Count == 0 {
			t.Fatalf("mode=%s missed match after long line: %v %+v", mode, err, out)
		}
	}
}
