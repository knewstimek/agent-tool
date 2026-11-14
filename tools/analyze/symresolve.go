package analyze

import (
	"debug/pe"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// vaOperations are the operations whose va/target_va name one address and
// accept a symbol name for it (decompile resolves its own list).
var vaOperations = map[string]bool{
	"disassemble": true, "function_at": true, "call_graph": true, "follow_ptr": true,
	"rtti_dump": true, "struct_layout": true, "hexdump": true, "xref": true,
}

// resolveSymbolArgs replaces a symbol name in va, target_va or
// target_end_va with its address. An agent reads names in decompile and
// disassembly output and passes them on; every operation but decompile
// used to answer "invalid va" with no way forward.
func resolveSymbolArgs(input *AnalyzeInput) error {
	for _, p := range []struct {
		field *string
		label string
	}{{&input.VA, "va"}, {&input.TargetVA, "target_va"}, {&input.TargetEndVA, "target_end_va"}} {
		s := strings.TrimSpace(*p.field)
		if s == "" {
			continue
		}
		if _, err := parseHexAddr(s); err == nil {
			continue
		}
		va, err := lookupSymbolVA(input.FilePath, input.PDBPath, input.PDBForce, s)
		if err != nil {
			return fmt.Errorf("%s: %v", p.label, err)
		}
		*p.field = fmt.Sprintf("0x%x", va)
	}
	return nil
}

// lookupSymbolVA finds name (optionally name+0xOFF) among the binary's own
// symbols (exports, imports at their IAT slots, ELF/Mach-O symbol tables),
// the matching PDB's functions and globals, and embedded DWARF's.
func lookupSymbolVA(path, pdbPath string, pdbForce bool, name string) (uint64, error) {
	base, add := name, uint64(0)
	if i := strings.LastIndex(name, "+"); i > 0 {
		if v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(name[i+1:]), "0x"), 16, 64); err == nil {
			base, add = strings.TrimSpace(name[:i]), v
		}
	}
	syms := fileSymbolNames(path, pdbPath, pdbForce)
	matches, similar := matchSymbol(syms, base)
	if len(matches) == 0 {
		// Embedded DWARF (ELF, MinGW/Go PE) names functions and globals
		// the symbol table may not; loaded only when needed.
		addDebugNames(syms, path, pdbPath, pdbForce)
		matches, similar = matchSymbol(syms, base)
	}
	if len(syms) == 0 {
		return 0, fmt.Errorf("%q is not a hex address, and the file has no symbol names to look it up in; pass a hex VA, e.g. 0x140001000", name)
	}
	switch {
	case len(matches) == 1:
		return matches[0] + add, nil
	case len(matches) > 1:
		return 0, fmt.Errorf("%q names %d symbols; pass one address: %s", base, len(matches), describeSymbols(syms, matches, 12))
	case len(similar) > 0:
		return 0, fmt.Errorf("%q is not a hex address or a known symbol; similar: %s", base, describeSymbols(syms, similar, 12))
	}
	return 0, fmt.Errorf("%q is not a hex address or a known symbol (exports, imports, symbol tables, PDB/DWARF functions and globals); pass a hex VA, e.g. 0x140001000", base)
}

// fileSymbolNames maps addresses to the names of the file's symbol tables
// and (PE) its matching PDB's functions and globals.
func fileSymbolNames(path, pdbPath string, pdbForce bool) map[uint64]string {
	syms := map[uint64]string{}
	if f, err := pe.Open(path); err == nil {
		imageBase := peImageBase(f)
		syms = peSymbolMap(f, imageBase, path)
		if pdbPath != "none" {
			mergePDBNames(syms, path, pdbPath, pdbForce, f, imageBase)
		}
		f.Close()
	} else if bin, err := cgOpenBinaryPDB(path, false); err == nil {
		for va, n := range bin.symbols {
			syms[va] = n
		}
		if bin.closer != nil {
			bin.closer()
		}
	}
	return syms
}

// addDebugNames adds the debug source's function and global names.
func addDebugNames(syms map[uint64]string, path, pdbPath string, pdbForce bool) {
	_ = withDebugInfo(path, pdbPath, pdbForce, func(ds debugSource) error {
		for va, n := range ds.functionNames() {
			if syms[va] == "" {
				syms[va] = n
			}
		}
		for va, n := range globalNames(ds) {
			if syms[va] == "" {
				syms[va] = n
			}
		}
		return nil
	})
}

func globalNames(ds debugSource) map[uint64]string {
	out := map[uint64]string{}
	switch v := ds.(type) {
	case *pdbInfo:
		for _, d := range v.data {
			out[d.va] = d.name
		}
	case *dwarfInfo:
		for _, d := range v.data {
			out[d.va] = d.name
		}
	}
	return out
}

// matchSymbol ranks names as decompile's lookupName does: exact (or display
// form), scope suffix, then the same ignoring case; a typo gets near names.
func matchSymbol(syms map[uint64]string, name string) (matches, similar []uint64) {
	vas := make([]uint64, 0, len(syms))
	for va := range syms {
		vas = append(vas, va)
	}
	sort.Slice(vas, func(i, j int) bool { return vas[i] < vas[j] })
	h := &decompHost{funcs: syms, starts: vas}
	return h.lookupName(name)
}

func describeSymbols(syms map[uint64]string, vas []uint64, n int) string {
	parts := make([]string, 0, min(len(vas), n)+1)
	for i, va := range vas {
		if i == n {
			parts = append(parts, fmt.Sprintf("... %d more", len(vas)-n))
			break
		}
		parts = append(parts, fmt.Sprintf("%s @ 0x%x", syms[va], va))
	}
	return strings.Join(parts, ", ")
}
