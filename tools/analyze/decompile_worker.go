package analyze

import (
	"debug/elf"
	"debug/pe"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/decomp"
	"github.com/knewstimek/gosleigh/pkg/loader"
	"github.com/knewstimek/gosleigh/pkg/pcode"
	"github.com/knewstimek/gosleigh/pkg/specs"
)

// DecompileWorkerArg is the hidden subcommand that turns this executable into
// a one-shot decompile worker. The MCP server re-executes itself with it
// (same binary, no extra file to ship) because the decompiler engine cannot
// be cancelled and can grow without bound on some functions: in a child
// process a timeout or memory blow-up kills only the worker.
const DecompileWorkerArg = "__decompile-worker"

// decompileRequest is the worker's stdin: one JSON object.
type decompileRequest struct {
	Path string `json:"path"`
	// PDBPath overrides where the PE's PDB is looked for; "none" disables it.
	PDBPath         string   `json:"pdb_path,omitempty"`
	Targets         []string `json:"targets"`
	MaxInstructions int      `json:"max_instructions,omitempty"`
	MemLimitMB      int      `json:"mem_limit_mb"`
}

// decompileLine is one JSON line of worker stdout. Lines are written as each
// step finishes, so the server keeps the results of the functions that
// completed before a timeout or a kill.
type decompileLine struct {
	Kind string `json:"kind"` // "load", "result" or "fatal"

	// load
	Format      string  `json:"format,omitempty"`
	Spec        string  `json:"spec,omitempty"`
	KnownStarts int     `json:"known_starts,omitempty"`
	NamedStarts int     `json:"named_starts,omitempty"`
	Imports     int     `json:"imports,omitempty"`
	LoadSecs    float64 `json:"load_secs,omitempty"`
	HostTracked string  `json:"tracked,omitempty"`
	PDB         string  `json:"pdb,omitempty"`      // PDB used
	PDBNote     string  `json:"pdb_note,omitempty"` // why no PDB was used

	// result (and fatal: the target that was running)
	Target    string   `json:"target,omitempty"`
	Entry     uint64   `json:"entry,omitempty"`
	Name      string   `json:"name,omitempty"`
	Note      string   `json:"note,omitempty"`
	C         string   `json:"c,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	ErrorKind string   `json:"error_kind,omitempty"` // input, load, engine, panic, memory
	Error     string   `json:"error,omitempty"`
	Secs      float64  `json:"secs,omitempty"`
}

// RunDecompileWorker serves one decompileRequest from in and writes
// decompileLines to out. It returns the process exit code.
func RunDecompileWorker(in io.Reader, out io.Writer) int {
	var mu sync.Mutex
	enc := json.NewEncoder(out)
	emit := func(l decompileLine) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(l)
	}

	var req decompileRequest
	if err := json.NewDecoder(io.LimitReader(in, 1<<20)).Decode(&req); err != nil {
		emit(decompileLine{Kind: "fatal", ErrorKind: "input", Error: "bad worker request: " + err.Error()})
		return 2
	}
	if req.MemLimitMB <= 0 {
		req.MemLimitMB = decompileMemLimitMB
	}
	limit := uint64(req.MemLimitMB) << 20

	var current atomic.Value // target being decompiled, for the memory report
	current.Store("")
	// The soft limit makes the GC work harder near the cap; the watchdog is the
	// hard stop, because a runaway rule loop keeps allocating live memory the
	// GC cannot free.
	debug.SetMemoryLimit(int64(limit))
	go func() {
		var ms runtime.MemStats
		for range time.Tick(200 * time.Millisecond) {
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > limit {
				emit(decompileLine{Kind: "fatal", ErrorKind: "memory", Target: current.Load().(string),
					Error: fmt.Sprintf("decompiler heap reached %d MB (limit %d MB)", ms.HeapAlloc>>20, req.MemLimitMB)})
				os.Exit(3)
			}
		}
	}()

	start := time.Now()
	t, err := loadDecompileTarget(req.Path, req.PDBPath)
	if err != nil {
		emit(decompileLine{Kind: "fatal", ErrorKind: "load", Error: err.Error()})
		return 1
	}
	emit(decompileLine{Kind: "load", Format: t.format, Spec: t.spec, KnownStarts: len(t.host.funcs),
		NamedStarts: t.host.named, Imports: len(t.host.imports), HostTracked: t.trackedDesc,
		PDB: t.pdb, PDBNote: t.pdbNote,
		LoadSecs: time.Since(start).Seconds()})

	for _, target := range req.Targets {
		current.Store(target)
		emit(t.decompile(target, req.MaxInstructions, false))
	}
	return 0
}

// decompileTarget is a loaded binary ready to decompile.
type decompileTarget struct {
	prog        *decomp.Program
	host        *decompHost
	format      string
	spec        string
	tracked     map[string]uint64
	trackedDesc string
	pdb         string // PDB whose names are applied
	pdbNote     string // why no PDB is applied (empty when none was expected)
	is64        bool
	exec        []execBytes
	// containing returns the start of the function that contains va when the
	// binary describes function extents exactly (x64 PE .pdata).
	containing func(va uint64) (uint64, bool)
}

// decompile decompiles one target. ghidraFormat selects Ghidra's exact
// layout, which only the golden measurement needs.
func (t *decompileTarget) decompile(target string, maxInstr int, ghidraFormat bool) decompileLine {
	line := decompileLine{Kind: "result", Target: target}
	entry, note, err := t.resolve(target)
	if err != nil {
		line.ErrorKind, line.Error = "input", err.Error()
		return line
	}
	line.Entry, line.Note = entry, note
	start := time.Now()
	res, err := t.prog.Decompile(decomp.Function{
		Entry:           entry,
		Name:            shortName(t.host.funcs[entry]),
		DisplayName:     t.host.funcs[entry],
		MaxInstructions: maxInstr,
		Host:            t.host,
		FlowOverrides:   tailCallOverrides(t, entry),
		TrackedRegs:     t.tracked,
		GhidraFormat:    ghidraFormat,
	})
	line.Secs = time.Since(start).Seconds()
	if err != nil {
		line.ErrorKind = "engine"
		msg := err.Error()
		if errors.Is(err, decomp.ErrPanic) {
			line.ErrorKind = "panic"
			msg, _, _ = strings.Cut(msg, "\n") // drop the stack trace
		}
		line.Error = msg
		return line
	}
	line.Name = t.host.nameOf(entry)
	line.C, line.Warnings = res.C, res.Warnings
	return line
}

// resolve turns a target (hex address or symbol name) into a function entry.
// Decompiling from the middle of a function produces plausible-looking
// garbage, so an address inside a function with an exactly known extent is
// moved to its start, and any other unknown start is flagged in the note.
func (t *decompileTarget) resolve(target string) (uint64, string, error) {
	va, err := parseHexAddr(target)
	if err != nil {
		if e, ok := t.host.lookupName(target); ok {
			return e, "", nil
		}
		return 0, "", fmt.Errorf("%q is neither a hex address nor a function name in this file (names come from PE exports, the matching PDB, and ELF symbol tables; use the qualified PDB form, e.g. Class::Method); pass va as hex, e.g. 0x140001000", target)
	}
	if !t.inExec(va) {
		return 0, "", fmt.Errorf("0x%x is not inside an executable section; check the address with analyze pe_info/elf_info", va)
	}
	if _, ok := t.host.funcs[va]; ok {
		return va, "", nil
	}
	if t.containing != nil {
		if begin, ok := t.containing(va); ok && begin != va {
			return begin, fmt.Sprintf("0x%x is inside the function starting at 0x%x (.pdata); decompiled that function", va, begin), nil
		}
	}
	note := fmt.Sprintf("0x%x is not a known function start", va)
	if prev, ok := t.host.precedingStart(va); ok {
		note += fmt.Sprintf(" (nearest known start before it: 0x%x)", prev)
	}
	note += "; the output is only meaningful if it really is an entry point -- confirm with analyze function_at"
	return va, note, nil
}

func (t *decompileTarget) inExec(va uint64) bool {
	_, ok := t.codeAt(va)
	return ok
}

// execBytes is one executable section at its virtual address, with its
// switch-table resolver (x86 PE only; nil otherwise).
type execBytes struct {
	vma  uint64
	data []byte
	jt   jtResolver
}

// loadDecompileTarget maps the binary, picks the embedded spec and builds the
// host symbol scope from what the file itself records.
func loadDecompileTarget(path, pdbPath string) (*decompileTarget, error) {
	bin, err := cgOpenBinary(path)
	if err != nil {
		return nil, fmt.Errorf("%v; decompile supports x86/x64 PE and ELF", err)
	}
	defer bin.closer()
	if bin.arch != "x86" && bin.arch != "x64" {
		return nil, fmt.Errorf("decompile supports x86 and x64 only, this %s binary is %s; use analyze disassemble instead", bin.format, bin.arch)
	}
	bits := 32
	if bin.is64 {
		bits = 64
	}

	t := &decompileTarget{format: bin.format + " " + bin.arch}
	var sections []decomp.Section
	compiler := specs.CompilerGCC
	var host *decompHost
	switch bin.format {
	case "PE":
		compiler = specs.CompilerWindows
		f, err := pe.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		// Same mapping the decompiler's golden measurement uses: raw section
		// data at ImageBase + VirtualAddress.
		secs, err := loader.LoadPESections(path)
		if err != nil {
			return nil, err
		}
		for _, s := range secs {
			sections = append(sections, decomp.Section{Name: s.Name, VMA: s.VMA, Data: s.Bytes})
		}
		var pd *pdataIndex
		if bits == 64 {
			if pd = loadPdata(f, bin.imageBase); pd != nil {
				t.containing = func(va uint64) (uint64, bool) { return pd.containing(bin.imageBase, va) }
			}
		}
		host = newPEHost(f, bin, pd)
		if pdbPath != "none" {
			var names *pdbNames
			names, t.pdbNote = loadPDBNames(path, pdbPath, f, bin.imageBase)
			if names != nil {
				t.pdb = names.path
				host.addNames(names.funcs, bin)
			}
		}
		// The segment bases Ghidra's PE loader sets for every function (FS for
		// x86 TEB access, GS for x64); observed in Ghidra 12 decompiler requests
		// for MSVC images. Without them fs:[0]/gs:[0x30] become unresolved
		// register reads.
		if bits == 32 {
			t.tracked = map[string]uint64{"FS_OFFSET": 0xffdff000}
			t.trackedDesc = "FS_OFFSET=0xffdff000"
		} else {
			t.tracked = map[string]uint64{"GS_OFFSET": 0xff00000000}
			t.trackedDesc = "GS_OFFSET=0xff00000000"
		}
	case "ELF":
		f, err := elf.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		for _, s := range f.Sections {
			if s.Flags&elf.SHF_ALLOC == 0 || s.Type == elf.SHT_NOBITS || s.Size == 0 {
				continue
			}
			data, err := s.Data()
			if err != nil {
				continue
			}
			sections = append(sections, decomp.Section{Name: s.Name, VMA: s.Addr, Data: data})
		}
		host = newELFHost(bin)
	default:
		return nil, fmt.Errorf("decompile supports PE and ELF, not %s", bin.format)
	}
	t.is64 = bin.is64
	var tables []tableSection
	if bin.format == "PE" {
		for _, s := range sections {
			tables = append(tables, tableSection{rva: uint32(s.VMA - bin.imageBase), data: s.Data})
		}
	}
	for _, s := range bin.execSections {
		e := execBytes{vma: bin.imageBase + uint64(s.rva), data: s.data}
		if tables != nil {
			e.jt = makeJumpTableResolver(tables, s.data, s.rva, bin.imageBase)
		}
		t.exec = append(t.exec, e)
	}

	spec, err := specs.X86(bits, compiler)
	if err != nil {
		return nil, err
	}
	if t.prog, err = decomp.Load(spec, sections); err != nil {
		return nil, err
	}
	t.spec, t.host = spec.ID, host
	return t, nil
}

// decompHost answers the decompiler core's symbol queries from the binary's
// own records: known function starts (.pdata, exports, symbol tables, call
// targets, the entry point) and import address table slots. It knows names
// only -- no prototypes or types -- so callee signatures stay unlocked and
// the core recovers them, as Ghidra does for a program without type info.
type decompHost struct {
	funcs   map[uint64]string // function entry -> name ("" = unnamed)
	starts  []uint64          // sorted keys of funcs
	imports map[uint64]string // import slot address -> imported name
	named   int
}

// addNames takes PDB function names and entries. A PDB entry is a real
// function even where the file's own records missed it, so it also becomes a
// known start (better callee names and tail-call detection).
func (h *decompHost) addNames(names map[uint64]string, bin *cgBinary) {
	for va, name := range names {
		if va < bin.imageBase || va-bin.imageBase > 0xffffffff || !isInExecSection(bin.execSections, uint32(va-bin.imageBase)) {
			continue
		}
		h.funcs[va] = name
	}
	h.finish()
}

func (h *decompHost) finish() {
	h.named = 0
	h.starts = make([]uint64, 0, len(h.funcs))
	for va, n := range h.funcs {
		h.starts = append(h.starts, va)
		if n != "" {
			h.named++
		}
	}
	sort.Slice(h.starts, func(i, j int) bool { return h.starts[i] < h.starts[j] })
}

// nameOf is the name Ghidra would show: the symbol, else FUN_<entry>.
func (h *decompHost) nameOf(va uint64) string {
	if n := h.funcs[va]; n != "" {
		return n
	}
	return fmt.Sprintf("FUN_%08x", va)
}

func (h *decompHost) QueryFunction(a address.Address) (pcode.HostFunction, bool) {
	if _, ok := h.funcs[a.Offset]; !ok {
		return pcode.HostFunction{}, false
	}
	name := h.nameOf(a.Offset)
	ns, _ := splitQualified(name)
	return pcode.HostFunction{Name: name, Namespace: ns, ExtraPop: pcode.ExtrapopUnknown}, true
}

func shortName(qualified string) string {
	_, n := splitQualified(qualified)
	return n
}

func (h *decompHost) QueryExternalRef(a address.Address) (string, bool) {
	n, ok := h.imports[a.Offset]
	return n, ok
}

func (h *decompHost) lookupName(name string) (uint64, bool) {
	var fold uint64
	found := false
	for va, n := range h.funcs {
		if n == name {
			return va, true
		}
		if !found && n != "" && strings.EqualFold(n, name) {
			fold, found = va, true
		}
	}
	return fold, found
}

func (h *decompHost) precedingStart(va uint64) (uint64, bool) {
	i := sort.Search(len(h.starts), func(i int) bool { return h.starts[i] > va })
	if i == 0 {
		return 0, false
	}
	return h.starts[i-1], true
}

func newPEHost(f *pe.File, bin *cgBinary, pd *pdataIndex) *decompHost {
	h := &decompHost{funcs: map[uint64]string{}, imports: map[uint64]string{}}
	exports := map[uint64]bool{}
	for _, e := range parseExports(f) {
		if !e.forwarder {
			exports[bin.imageBase+uint64(e.rva)] = true
		}
	}
	for _, fr := range bin.funcTable {
		if pd != nil {
			if _, chained := pd.primary[fr.begin]; chained {
				continue // a function part, not a function
			}
		}
		h.funcs[bin.imageBase+uint64(fr.begin)] = ""
	}
	// peSymbolMap mixes export names (at code) with import names (at IAT
	// slots); a slot is never a function start.
	for va, name := range bin.symbols {
		if exports[va] {
			h.funcs[va] = name
		} else {
			h.imports[va] = name
		}
	}
	var entryRVA uint32
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entryRVA = oh.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		entryRVA = oh.AddressOfEntryPoint
	}
	if entryRVA != 0 {
		if va := bin.imageBase + uint64(entryRVA); h.funcs[va] == "" {
			h.funcs[va] = "entry" // Ghidra's name for the PE entry point
		}
	}
	h.finish()
	return h
}

func newELFHost(bin *cgBinary) *decompHost {
	h := &decompHost{funcs: map[uint64]string{}, imports: map[uint64]string{}}
	for _, fr := range bin.funcTable {
		va := bin.imageBase + uint64(fr.begin)
		h.funcs[va] = bin.symbols[va]
	}
	h.finish()
	return h
}
