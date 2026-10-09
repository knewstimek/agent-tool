package analyze

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestSplitQualified(t *testing.T) {
	for _, c := range []struct{ in, ns, name string }{
		{"main", "", "main"},
		{"FActiveSound::SetWaveParameter", "FActiveSound", "SetWaveParameter"},
		{"A::B<C::D>::f", "A::B<C::D>", "f"},
		{"GlobalVectorConstants::`dynamic initializer for 'A::B''", "GlobalVectorConstants", "`dynamic initializer for 'A::B''"},
		{"std::vector<int>::operator()", "std::vector<int>", "operator()"},
		{"f(A::B)", "", "f(A::B)"},
	} {
		ns, name := splitQualified(c.in)
		if ns != c.ns || name != c.name {
			t.Errorf("splitQualified(%q) = %q, %q; want %q, %q", c.in, ns, name, c.ns, c.name)
		}
	}
}

func cvRecord(kind uint16, payload []byte) []byte {
	b := make([]byte, 4, 4+len(payload))
	binary.LittleEndian.PutUint16(b, uint16(2+len(payload)))
	binary.LittleEndian.PutUint16(b[2:], kind)
	return append(b, payload...)
}

func TestWalkCVSymbolsStopsOnTruncation(t *testing.T) {
	pub := make([]byte, 10)
	binary.LittleEndian.PutUint32(pub, cvPubFunction)
	pub = append(pub, "_main\x00"...)
	stream := append(cvRecord(cvSPub32, pub), cvRecord(cvSGData32, make([]byte, 12))...)
	stream = append(stream, 0xff, 0x7f, 0x0e, 0x11) // length runs past the end
	var kinds []uint16
	walkCVSymbols(stream, func(k uint16, rec []byte) { kinds = append(kinds, k) })
	if len(kinds) != 2 || kinds[0] != cvSPub32 || kinds[1] != cvSGData32 {
		t.Fatalf("kinds = %#x", kinds)
	}
}

func TestOpenPDBRejectsNonPDB(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"empty.pdb":     nil,
		"text.pdb":      []byte("not a program database at all, just some text padding here"),
		"truncated.pdb": msfMagic,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if p, err := openPDB(path); err == nil {
			p.Close()
			t.Errorf("%s: openPDB accepted it", name)
		}
	}
}

// AGENT_TOOL_PDB=<file.pdb> runs the reader on a real PDB.
func TestPDBRealFile(t *testing.T) {
	path := os.Getenv("AGENT_TOOL_PDB")
	if path == "" {
		t.Skip("set AGENT_TOOL_PDB to a PDB file")
	}
	p, err := openPDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.info(); err != nil {
		t.Fatal(err)
	}
	syms, err := p.symbols()
	if err != nil {
		t.Fatal(err)
	}
	if syms.modules == 0 || len(syms.procs)+len(syms.publics) == 0 {
		t.Fatalf("no symbols: modules=%d procs=%d publics=%d", syms.modules, len(syms.procs), len(syms.publics))
	}
	t.Logf("modules=%d procs=%d publics=%d globals=%d", syms.modules, len(syms.procs), len(syms.publics), len(syms.globals))
}
