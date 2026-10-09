package analyze

import (
	"debug/pe"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// xrefLocator names the function (or data object) an address sits in, so a
// reference list reads "in World::Tick+0x42" instead of a bare address the
// agent would have to resolve with one function_at call per line.
type xrefLocator struct {
	imageBase uint64
	ptrSize   uint64
	funcs     []funcRange
	symbols   map[uint64]string
	symVAs    []uint64 // sorted keys of symbols
	pdb       *pdbNameIndex
}

// newXrefLocator builds the function table call_graph uses (pdata, exports,
// vtable pointers and the cached linear sweep) plus file and PDB names. It
// returns nil when the binary cannot be read; references are then printed
// without locations.
func newXrefLocator(path, pdbPath string, pdbForce bool) *xrefLocator {
	cg, err := cgOpenBinaryPDB(path, false)
	if err != nil {
		return nil
	}
	defer cg.closer()
	l := &xrefLocator{imageBase: cg.imageBase, ptrSize: 4, funcs: cg.funcTable, symbols: cg.symbols}
	if cg.is64 || cg.arch == "arm64" {
		l.ptrSize = 8
	}
	if cg.format == "PE" && pdbPath != "none" {
		if f, err := pe.Open(path); err == nil {
			mergePDBNames(l.symbols, path, pdbPath, pdbForce, f, cg.imageBase)
			l.pdb, _ = loadPDBNameIndex(path, pdbPath, pdbForce, f, cg.imageBase)
			f.Close()
		}
	}
	l.symVAs = make([]uint64, 0, len(l.symbols))
	for va := range l.symbols {
		l.symVAs = append(l.symVAs, va)
	}
	sort.Slice(l.symVAs, func(i, j int) bool { return l.symVAs[i] < l.symVAs[j] })
	return l
}

// function returns "name+0xoff" for the function containing va, "" if none.
// PDB procedure bounds are exact; otherwise the heuristic table decides.
func (l *xrefLocator) function(va uint64) (string, uint64) {
	if l == nil {
		return "", 0
	}
	if l.pdb != nil {
		if r, ok := l.pdb.procAt(va); ok {
			return withOffset(r.name, va-r.start), r.start
		}
	}
	if va < l.imageBase || va-l.imageBase > 0xFFFFFFFF {
		return "", 0
	}
	fn := findFunc(l.funcs, uint32(va-l.imageBase))
	if fn == nil {
		return "", 0
	}
	start := l.imageBase + uint64(fn.entry())
	name := l.symbols[start]
	if name == "" {
		name = fmt.Sprintf("sub_%x", start)
	}
	if va < start { // a split-off cold block placed before its function
		return fmt.Sprintf("%s (cold part at 0x%x)", name, l.imageBase+uint64(fn.begin)), start
	}
	return withOffset(name, va-start), start
}

// data labels a pointer slot by the nearest named object before it; slots in
// a vftable also get their index, which is what a virtual call site uses.
func (l *xrefLocator) data(va uint64) string {
	if l == nil {
		return ""
	}
	i := sort.Search(len(l.symVAs), func(i int) bool { return l.symVAs[i] > va })
	if i == 0 {
		return ""
	}
	at := l.symVAs[i-1]
	off := va - at
	if off > 0x10000 {
		return ""
	}
	name := l.symbols[at]
	s := withOffset(name, off)
	if strings.Contains(name, "vftable") || strings.Contains(name, "vtable") || strings.HasPrefix(name, "_ZTV") {
		s += fmt.Sprintf(" (slot %d)", off/l.ptrSize)
	}
	return s
}

func withOffset(name string, off uint64) string {
	if off == 0 {
		return name
	}
	return fmt.Sprintf("%s+0x%x", name, off)
}

// lineVA reads the address every reference line starts with ("  0x...:").
func (r xrefResult) lineVA() uint64 {
	s := strings.TrimSpace(r.line)
	if end := strings.IndexByte(s, ':'); end > 2 && strings.HasPrefix(s, "0x") {
		if v, err := strconv.ParseUint(s[2:end], 16, 64); err == nil {
			return v
		}
	}
	return 0
}

// annotate appends each reference's location and upgrades an address load
// that feeds a register call (lea rax, [f]; call rax) to a CALL. It returns
// how many distinct functions the references come from.
func annotateXrefs(bin *xrefBinary, loc *xrefLocator, refs []xrefResult) int {
	mode := 0
	switch bin.arch {
	case "x64":
		mode = 64
	case "x86":
		mode = 32
	}
	funcs := map[uint64]bool{}
	for i := range refs {
		r := &refs[i]
		va := r.lineVA()
		var notes []string
		if r.refType == "PTR" {
			if d := loc.data(va); d != "" {
				notes = append(notes, "in "+d)
			}
		} else {
			if mode != 0 && (r.refType == "LEA" || r.refType == "MOV") {
				if data, off, ok := bin.codeAt(va); ok {
					if use, at, ok := indirectUse(data, off, mode, va); ok {
						r.refType = strings.ToUpper(strings.Fields(use)[0])
						notes = append(notes, fmt.Sprintf("then %s at 0x%x", use, at))
					}
				}
			}
			if name, start := loc.function(va); name != "" {
				funcs[start] = true
				notes = append(notes, "in "+name)
			}
		}
		if len(notes) > 0 {
			r.line = strings.TrimRight(r.line, "\n") + "  ; " + strings.Join(notes, "; ") + "\n"
		}
	}
	return len(funcs)
}

// codeAt returns the executable section bytes from va on.
func (b *xrefBinary) codeAt(va uint64) ([]byte, int, bool) {
	if va < b.imageBase {
		return nil, 0, false
	}
	rva := va - b.imageBase
	for _, s := range b.sections {
		if rva >= uint64(s.rva) && rva < uint64(s.rva)+uint64(len(s.data)) {
			return s.data, int(rva - uint64(s.rva)), true
		}
	}
	return nil, 0, false
}

// rootDataRefs lists the data slots holding va (vtable entries, callback
// tables) as located lines, for call_graph's view of a function that is only
// called indirectly. At most 20.
func rootDataRefs(path string, va uint64, symbols map[uint64]string) []string {
	bin, err := xrefOpen(path)
	if err != nil {
		return nil
	}
	refs, _ := collectXrefData(bin, bin.target(va, va), 20, 0, nil)
	if len(refs) == 0 {
		return nil
	}
	// Data slots only need names: call_graph's symbols are enough.
	loc := &xrefLocator{imageBase: bin.imageBase, ptrSize: 4, symbols: symbols}
	if bin.arch == "x64" || bin.arch == "arm64" {
		loc.ptrSize = 8
	}
	for a := range symbols {
		loc.symVAs = append(loc.symVAs, a)
	}
	sort.Slice(loc.symVAs, func(i, j int) bool { return loc.symVAs[i] < loc.symVAs[j] })
	annotateXrefs(bin, loc, refs)
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.line
	}
	return out
}
