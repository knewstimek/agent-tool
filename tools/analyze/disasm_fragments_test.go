package analyze

import (
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A split function's first .pdata range must not end the output silently:
// the note names the function's other ranges.
func TestDisassembleNotesChainedFragments(t *testing.T) {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "ntdll.dll")
	f, err := pe.Open(path)
	if err != nil {
		t.Skip("needs an x64 Windows system DLL with chained unwind info")
	}
	imageBase := peImageBase(f)
	pd := loadPdata(f, imageBase)
	f.Close()
	if pd == nil || len(pd.primary) == 0 {
		t.Skip("no chained .pdata entries")
	}
	// Ranges under maxDisasmCount bytes always fit in one call (an
	// instruction is at least one byte), so the cap cannot pre-empt the note.
	var owner, frag uint32
	for _, fr := range pd.table {
		p, ok := pd.primary[fr.begin]
		if !ok || fr.end-fr.begin >= maxDisasmCount {
			continue
		}
		if o := findFunc(pd.table, p); o != nil && o.end-o.begin < maxDisasmCount {
			owner, frag = p, fr.begin
			break
		}
	}
	if owner == 0 {
		t.Skip("no small split function")
	}

	// The decompiler's flow bounds: the owner's range plus every fragment,
	// and nothing for an address that is only a fragment.
	ext := pd.extent(imageBase, imageBase+uint64(owner))
	hasFrag := false
	for _, r := range ext {
		hasFrag = hasFrag || r[0] == imageBase+uint64(frag)
	}
	if len(ext) < 2 || !hasFrag {
		t.Errorf("extent(owner) = %#x, want the owner and fragment 0x%x", ext, imageBase+uint64(frag))
	}
	if e := pd.extent(imageBase, imageBase+uint64(frag)); e != nil {
		t.Errorf("extent(fragment) = %#x, want nil", e)
	}

	for _, tc := range []struct {
		va   uint32
		want string
	}{
		{owner, fmt.Sprintf("0x%x-", imageBase+uint64(frag))},
		{frag, fmt.Sprintf("split-off fragment of the function at 0x%x", imageBase+uint64(owner))},
	} {
		out, err := opDisassemble(AnalyzeInput{FilePath: path, VA: fmt.Sprintf("0x%x", imageBase+uint64(tc.va)), Count: maxDisasmCount})
		if err != nil {
			t.Fatal(err)
		}
		t.Log(tail(out))
		if !strings.Contains(out, "reached the end of this .pdata range") || !strings.Contains(out, tc.want) {
			t.Errorf("va 0x%x: no fragment note naming %q:\n%s", imageBase+uint64(tc.va), tc.want, tail(out))
		}
	}
}

func tail(s string) string {
	if len(s) > 600 {
		return s[len(s)-600:]
	}
	return s
}
