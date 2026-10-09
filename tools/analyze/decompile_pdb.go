package analyze

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/knewstimek/gopdb"
	"github.com/knewstimek/gopdb/demangle"
	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// peCodeView is the PE debug directory's RSDS record: which PDB was built
// with this image.
type peCodeView struct {
	path string
	guid pdb.GUID
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
		cv.path = strings.TrimRight(string(rec[24:]), "\x00")
		if i := strings.IndexByte(cv.path, 0); i >= 0 {
			cv.path = cv.path[:i]
		}
		return cv, true
	}
	return peCodeView{}, false
}

// pdbInfo is what the decompile host takes from a matching PDB.
type pdbInfo struct {
	path  string
	funcs map[uint64]*pdbFunc // entry VA -> function
	data  []pdbData           // sorted by VA
	types *pdbTypes
}

type pdbFunc struct {
	name  string           // qualified, as recorded (see ghidraName)
	proc  *pdb.Procedure   // full debug info, or
	dem   *demangle.Symbol // a decorated public's decoding
	proto *pcode.HostFunction
	built bool // proto computed (may be nil)
}

type pdbData struct {
	va   uint64
	name string // qualified, as recorded
	typ  pdb.TypeIndex
	size uint64
}

// openPDBInfo finds the PDB that belongs to the image -- override when
// given, else the RSDS path, then the RSDS file name and the image's own
// name beside the image -- and checks its GUID. A missing PDB is not an
// error; a PDB with a different GUID is reported and not used: its
// addresses describe another build. force (with an override only) loads it
// anyway -- a relinked or patched image whose code still matches -- and the
// note then warns that names and types may be misplaced.
func openPDBInfo(exePath, override string, force bool, f *pe.File, imageBase uint64, is64 bool) (*pdbInfo, string) {
	force = force && override != ""
	cv, ok := readPECodeView(f)
	if !ok && !force {
		if override != "" {
			return nil, "the image has no RSDS debug record, so pdb_path cannot be matched to it; pass pdb_force=true to load it unchecked"
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
	var note string
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err != nil || st.IsDir() {
			continue
		}
		p, err := pdb.Open(c)
		if err != nil {
			note = fmt.Sprintf("PDB %s unreadable: %v", c, err)
			continue
		}
		info, err := p.Info()
		var warn string
		if err != nil || !ok || info.GUID != cv.guid {
			if !force {
				p.Close()
				note = fmt.Sprintf("PDB %s does not match this image (GUID differs); not used. If it is the same build (relinked or patched image), pass pdb_force=true", c)
				continue
			}
			warn = "forced with pdb_force: the GUID does not match the image, so names, types and locals may sit at the wrong addresses if the code differs"
		}
		pi, err := loadPDBInfo(c, p, imageBase, is64)
		if err != nil {
			p.Close()
			return nil, fmt.Sprintf("PDB %s: %v", c, err)
		}
		// The type table stays in use for lazy conversion; the file itself is
		// fully read into memory by then.
		p.Close()
		return pi, warn
	}
	if note != "" {
		return nil, note
	}
	if override != "" {
		return nil, fmt.Sprintf("pdb_path %s not found", override)
	}
	return nil, fmt.Sprintf("PDB %s not found beside the image; pass pdb_path to use it", base)
}

func loadPDBInfo(path string, p *pdb.File, imageBase uint64, is64 bool) (*pdbInfo, error) {
	dbi, err := p.DBI()
	if err != nil {
		return nil, err
	}
	tt, err := p.Types()
	if err != nil {
		return nil, err
	}
	ids, _ := p.IDs()
	pi := &pdbInfo{path: path, funcs: map[uint64]*pdbFunc{}, types: newPDBTypes(tt, ids, is64)}
	va := func(seg uint16, off uint32) (uint64, bool) {
		rva, ok := dbi.RVA(seg, off)
		return imageBase + uint64(rva), ok
	}
	// Names and prototypes in order of precedence: procedure records (full
	// debug info: undecorated qualified name, procedure type, parameter
	// records), then decorated publics decoded by the demangler (code built
	// without full debug info, as Ghidra does), then thunk records.
	var thunks []*pdb.Thunk
	// Modules are read and decoded in parallel (independent streams; most
	// of the PDB load on a large program; analysisThreads workers), then
	// merged in module order so
	// the result is the same as a sequential read.
	modSyms := make([][]pdb.Symbol, len(dbi.Modules))
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < analysisThreads(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				modSyms[i], _ = p.ModuleSymbols(dbi.Modules[i])
			}
		}()
	}
	for i := range dbi.Modules {
		next <- i
	}
	close(next)
	wg.Wait()
	for _, syms := range modSyms {
		for _, s := range syms {
			switch v := s.(type) {
			case *pdb.Procedure:
				if v.Name == "" {
					continue
				}
				if a, ok := va(v.Segment, v.Offset); ok {
					pi.funcs[a] = &pdbFunc{name: v.Name, proc: v}
				}
			case *pdb.Thunk:
				thunks = append(thunks, v)
			}
		}
	}
	globals, err := p.GlobalSymbols()
	if err != nil {
		return nil, err
	}
	seen := map[uint64]bool{}
	for _, s := range globals {
		switch g := s.(type) {
		case *pdb.Public:
			if g.Flags&pdb.PublicFunction == 0 || g.Name == "" {
				continue
			}
			a, ok := va(g.Segment, g.Offset)
			if !ok || pi.funcs[a] != nil {
				continue
			}
			if g.Name[0] != '?' {
				pi.funcs[a] = &pdbFunc{name: g.Name}
			} else if sym, err := demangle.Demangle(g.Name); err == nil && sym.Kind == demangle.KindFunction {
				pi.funcs[a] = &pdbFunc{name: demangledName(sym), dem: sym}
			}
		case *pdb.Data:
			if g.Kind() != pdb.SGData32 && g.Kind() != pdb.SLData32 {
				continue // thread-local storage is not at a fixed address
			}
			a, ok := va(g.Segment, g.Offset)
			if !ok || seen[a] {
				continue
			}
			size := pi.types.size(g.Type)
			if size == 0 {
				continue
			}
			seen[a] = true
			pi.data = append(pi.data, pdbData{va: a, name: g.Name, typ: g.Type, size: size})
		}
	}
	for _, th := range thunks {
		if a, ok := va(th.Segment, th.Offset); ok && pi.funcs[a] == nil && th.Name != "" {
			pi.funcs[a] = &pdbFunc{name: th.Name}
		}
	}
	sort.Slice(pi.data, func(i, j int) bool { return pi.data[i].va < pi.data[j].va })
	return pi, nil
}

// prototype is the locked prototype of the function at va, nil when the
// PDB has no usable type for it.
func (pi *pdbInfo) prototype(va uint64) *pcode.HostFunction {
	f := pi.funcs[va]
	if f == nil {
		return nil
	}
	if !f.built {
		f.built = true
		switch {
		case f.proc != nil:
			f.proto = pi.types.prototype(f.proc)
		case f.dem != nil:
			f.proto = pi.types.demangledPrototype(f.dem)
		}
	}
	return f.proto
}

// dataAt is the global variable whose storage contains va.
func (pi *pdbInfo) globalAt(va uint64) (pdbData, bool) {
	i := sort.Search(len(pi.data), func(i int) bool { return pi.data[i].va > va })
	if i == 0 {
		return pdbData{}, false
	}
	d := pi.data[i-1]
	return d, va < d.va+d.size
}

// ghidraName is the form Ghidra shows a PDB name in: spaces inside template
// arguments and operator names become underscores, and MSVC's quoted
// compiler names (`vftable') lose their quotes.
func ghidraName(n string) string {
	n = strings.ReplaceAll(n, "`vftable'", "vftable")
	n = strings.ReplaceAll(n, "`vbtable'", "vbtable")
	return strings.ReplaceAll(n, " ", "_")
}

// displayParts splits a recorded qualified name into its namespace and name
// in display form.
func displayParts(raw string) (ns, name string) {
	ns, name = splitQualified(raw)
	return ghidraName(ns), ghidraName(name)
}

// splitQualified splits "A::B<C::D>::f" into namespace "A::B<C::D>" and
// name "f": only top-level "::" separate scopes (not inside template
// arguments, parentheses or `quoted' compiler names). MSVC nests quotes --
// "`dynamic initializer for 'A::B”" -- so inside a quote a ' after a space
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

// QueryData answers the core's global-symbol queries from the debug
// information's data symbols.
// C++ parity of the consumer: ScopeGhidra::findContainer.
func (h *decompHost) QueryData(a address.Address) (pcode.HostData, bool) {
	if h.debug == nil {
		return pcode.HostData{}, false
	}
	raw, start, t, ok := h.debug.dataAt(a.Offset)
	if !ok {
		return pcode.HostData{}, false
	}
	ns, name := displayParts(raw)
	return pcode.HostData{Name: name, Namespace: ns, Addr: address.Address{Space: a.Space, Offset: start},
		Size: t.Size(), Type: t, ReadOnly: h.readOnly(start)}, true
}

// Property marks addresses in non-writable sections read-only, as Ghidra's
// PE loader does for their memory blocks, so the core may fold loads from
// constant tables. C++ parity of the consumer: Database::getProperty.
func (h *decompHost) Property(a address.Address) uint32 {
	if h.readOnly(a.Offset) {
		return pcode.VarnodeReadOnly
	}
	return 0
}

func (h *decompHost) readOnly(va uint64) bool {
	for _, r := range h.roRanges {
		if va >= r[0] && va < r[1] {
			return true
		}
	}
	return false
}
