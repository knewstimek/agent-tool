package analyze

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDecompileRealexeAdapter measures the file-only host adapter against
// the decompiler's real-binary goldens: the same functions Ghidra decompiled
// with its full program database (PDB, analysis, types). It writes one
// goldengap-format JSON per work for Gosleigh's classifier to score; the gap
// to the full-host 200/200 is what the adapter does not know.
//
//	AGENT_TOOL_REALEXE_DIR=<gosleigh>/local/realexe  (works with meta.json + goldens.json)
//	AGENT_TOOL_REALEXE_WORKS=<work>,<work>
//	AGENT_TOOL_REALEXE_OUT=<dir for adapter_<work>.json>
func TestDecompileRealexeAdapter(t *testing.T) {
	dir, works, outDir := os.Getenv("AGENT_TOOL_REALEXE_DIR"), os.Getenv("AGENT_TOOL_REALEXE_WORKS"), os.Getenv("AGENT_TOOL_REALEXE_OUT")
	if dir == "" || works == "" || outDir == "" {
		t.Skip("set AGENT_TOOL_REALEXE_DIR, AGENT_TOOL_REALEXE_WORKS and AGENT_TOOL_REALEXE_OUT")
	}
	for _, work := range strings.Split(works, ",") {
		t.Run(work, func(t *testing.T) {
			var meta struct {
				Exe string `json:"exe"`
			}
			readJSON(t, filepath.Join(dir, work, "meta.json"), &meta)
			var goldens struct {
				Functions []struct {
					Name          string      `json:"name"`
					Entry         json.Number `json:"entry"`
					FlowOverrides []struct {
						Addr uint64 `json:"addr"`
						Type string `json:"type"`
					} `json:"flowoverrides"`
				} `json:"functions"`
			}
			readJSON(t, filepath.Join(dir, work, "goldens.json"), &goldens)

			target, err := loadDecompileTarget(meta.Exe)
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				Name   string `json:"name"`
				Output string `json:"output"`
				Error  string `json:"error,omitempty"`
			}
			var out struct {
				Functions []result `json:"functions"`
			}
			failed := 0
			// Tail-call overrides vs the CALL_RETURN overrides Ghidra's analysis set.
			var hit, extra, missed int
			for _, g := range goldens.Functions {
				entry, err := g.Entry.Int64()
				if err != nil {
					t.Fatal(err)
				}
				want := map[uint64]bool{}
				for _, fo := range g.FlowOverrides {
					if fo.Type == "CALL_RETURN" {
						want[fo.Addr] = true
					}
				}
				got := tailCallOverrides(target, uint64(entry))
				for a := range got {
					if want[a] {
						hit++
					} else {
						extra++
						t.Logf("extra CALL_RETURN at 0x%x in %s", a, g.Name)
					}
				}
				for a := range want {
					if _, ok := got[a]; !ok {
						missed++
						t.Logf("missed CALL_RETURN at 0x%x in %s", a, g.Name)
					}
				}
				l := target.decompile(fmt.Sprintf("0x%x", entry), 20000, true)
				r := result{Name: g.Name, Output: l.C}
				if l.Error != "" {
					r.Error = l.ErrorKind + ": " + l.Error
					failed++
				}
				out.Functions = append(out.Functions, r)
			}
			data, _ := json.MarshalIndent(out, "", "  ")
			path := filepath.Join(outDir, "adapter_"+work+".json")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: %d functions, %d errors -> %s", work, len(out.Functions), failed, path)
			t.Logf("%s: tail-call overrides: %d match Ghidra, %d extra, %d missed", work, hit, extra, missed)
		})
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}
