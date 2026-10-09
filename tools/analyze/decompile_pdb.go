package analyze

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// peCodeView is the PE debug directory's RSDS record: which PDB was built
// with this image.
type peCodeView struct {
	path string
	guid [16]byte
	age  uint32
}

func readPECodeView(f *pe.File) (peCodeView, bool) {
	var dir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 6 {
			dir = oh.DataDirectory[6]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 6 {
			dir = oh.DataDirectory[6]
		}
	}
	readRVA := func(rva uint32, n int) []byte {
		for _, s := range f.Sections {
			if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
				buf := make([]byte, n)
				m, _ := s.ReadAt(buf, int64(rva-s.VirtualAddress))
				return buf[:m]
			}
		}
		return nil
	}
	ents := readRVA(dir.VirtualAddress, int(min(dir.Size, 28*64)))
	for i := 0; i+28 <= len(ents); i += 28 {
		const imageDebugTypeCodeView = 2
		if binary.LittleEndian.Uint32(ents[i+12:]) != imageDebugTypeCodeView {
			continue
		}
		size := binary.LittleEndian.Uint32(ents[i+16:])
		rec := readRVA(binary.LittleEndian.Uint32(ents[i+20:]), int(min(size, 1024)))
		if len(rec) < 24 || string(rec[:4]) != "RSDS" {
			continue
		}
		var cv peCodeView
		copy(cv.guid[:], rec[4:20])
		cv.age = binary.LittleEndian.Uint32(rec[20:])
		cv.path = cString(rec[24:])
		return cv, true
	}
	return peCodeView{}, false
}

// pdbNames is what the decompile host takes from a PDB: function entries
// with their qualified names (VA -> name).
type pdbNames struct {
	path  string
	funcs map[uint64]string
}

// loadPDBNames finds the PDB that belongs to the image -- override when given,
// else the RSDS path, then the RSDS file name and the image's own name beside
// the image -- checks its GUID, and reads function names. A missing PDB is
// not an error; a PDB with a different GUID is reported, not used: its
// addresses describe another build.
func loadPDBNames(exePath, override string, f *pe.File, imageBase uint64) (*pdbNames, string) {
	cv, ok := readPECodeView(f)
	if !ok {
		if override != "" {
			return nil, "the image has no RSDS debug record, so pdb_path cannot be matched to it"
		}
		return nil, ""
	}
	// RSDS paths are the build machine's (often absolute Windows paths), so
	// split on both separators to take the file name.
	base := cv.path[strings.LastIndexAny(cv.path, `\/`)+1:]
	candidates := []string{override}
	if override == "" {
		dir := filepath.Dir(exePath)
		candidates = []string{cv.path, filepath.Join(dir, base),
			strings.TrimSuffix(exePath, filepath.Ext(exePath)) + ".pdb"}
	}
	var mismatch string
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err != nil || st.IsDir() {
			continue
		}
		p, err := openPDB(c)
		if err != nil {
			mismatch = fmt.Sprintf("PDB %s unreadable: %v", c, err)
			continue
		}
		info, err := p.info()
		if err != nil || !bytes.Equal(info.guid[:], cv.guid[:]) {
			p.Close()
			mismatch = fmt.Sprintf("PDB %s does not match this image (GUID differs); not used", c)
			continue
		}
		syms, err := p.symbols()
		p.Close()
		if err != nil {
			return nil, fmt.Sprintf("PDB %s: %v", c, err)
		}
		return buildPDBNames(c, syms, f, imageBase), ""
	}
	if mismatch != "" {
		return nil, mismatch
	}
	if override != "" {
		return nil, fmt.Sprintf("pdb_path %s not found", override)
	}
	return nil, fmt.Sprintf("PDB %s not found beside the image; pass pdb_path to use it", base)
}

func buildPDBNames(path string, syms *pdbSymbols, f *pe.File, imageBase uint64) *pdbNames {
	va := func(s pdbSymbol) (uint64, bool) {
		if s.segment == 0 || int(s.segment) > len(f.Sections) {
			return 0, false
		}
		return imageBase + uint64(f.Sections[s.segment-1].VirtualAddress) + uint64(s.offset), true
	}
	n := &pdbNames{path: path, funcs: map[uint64]string{}}
	// Procedure records carry undecorated, qualified names ("Class::Method"),
	// what Ghidra shows; publics are only a fallback for entries no module
	// describes, and only when undecorated (a decorated "?..." name would need
	// a demangler).
	for _, s := range syms.procs {
		if a, ok := va(s); ok && s.name != "" {
			n.funcs[a] = s.name
		}
	}
	for _, s := range syms.publics {
		if !s.function || s.name == "" || s.name[0] == '?' {
			continue
		}
		if a, ok := va(s); ok {
			if _, have := n.funcs[a]; !have {
				n.funcs[a] = s.name
			}
		}
	}
	return n
}

// splitQualified splits "A::B<C::D>::f" into namespace "A::B<C::D>" and
// name "f": only top-level "::" separate scopes (not inside template
// arguments, parentheses or `quoted' compiler names). MSVC nests quotes --
// "`dynamic initializer for 'A::B''" -- so inside a quote a ' after a space
// or a backtick opens an inner quote and any other ' closes one.
func splitQualified(q string) (ns, name string) {
	depth := 0
	quote := 0
	last := -1
	for i := 0; i < len(q); i++ {
		switch c := q[i]; {
		case c == '`':
			quote++
		case c == '\'' && quote > 0:
			if p := q[i-1]; p == ' ' || p == '`' {
				quote++
			} else {
				quote--
			}
		case quote > 0:
		case c == '<' || c == '(' || c == '[':
			depth++
		case (c == '>' || c == ')' || c == ']') && depth > 0:
			depth--
		case c == ':' && depth == 0 && i+1 < len(q) && q[i+1] == ':':
			last = i
			i++
		}
	}
	if last < 0 {
		return "", q
	}
	return q[:last], q[last+2:]
}
