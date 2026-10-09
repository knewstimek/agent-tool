package analyze

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decompile-all writes one entry per function and resumes a partial file
// without repeating the functions it already holds.
func TestDecompileAllCorpus(t *testing.T) {
	exe := filepath.Join("testdata", "pdb", "fixture_x64.exe")
	out := filepath.Join(t.TempDir(), "corpus.jsonl")
	var log bytes.Buffer
	if code := RunDecompileAll([]string{"-j", "2", "-limit", "4", "-o", out, exe}, &log); code != 0 {
		t.Fatalf("exit %d:\n%s", code, log.String())
	}
	if code := RunDecompileAll([]string{"-j", "2", "-o", out, exe}, &log); code != 0 {
		t.Fatalf("resume exit %d:\n%s", code, log.String())
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seen := map[string]bool{}
	named := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	for sc.Scan() {
		var e corpusEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad line %q: %v", sc.Text(), err)
		}
		if seen[e.Entry] {
			t.Errorf("%s written twice", e.Entry)
		}
		seen[e.Entry] = true
		if e.Name == "use_node" && strings.Contains(e.C, "use_node(Node *n, Color c)") {
			named = true
		}
	}
	if len(seen) <= 4 || !named {
		t.Errorf("%d entries, use_node found: %v\n%s", len(seen), named, log.String())
	}
	if !strings.Contains(log.String(), "4 already in") {
		t.Errorf("resume did not skip the first run's functions:\n%s", log.String())
	}
}
