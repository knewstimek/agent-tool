package analyze

import (
	"bytes"
	"context"
	"debug/dwarf"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/knewstimek/gosleigh/pkg/pcode"
	"golang.org/x/arch/x86/x86asm"
)

const (
	defaultXrefFieldFuncs = 32
	maxXrefFieldFuncs     = 128
	defaultXrefFieldSecs  = 120
)

// opXrefField answers "which functions access Class::member". The field's
// offset comes from the PDB or DWARF. Candidates are the functions with an
// instruction addressing [reg+offset] -- found through the offset's bytes for
// a disp32, and among the class's own methods for a disp8 offset, which is
// too common to search the whole binary for. Every candidate is decompiled
// with the debug types applied: one whose C names the member is a confirmed
// access, the rest only share the offset (another type, or untyped code).
func opXrefField(ctx context.Context, input AnalyzeInput) (string, error) {
	i := strings.LastIndex(input.Field, "::")
	if i <= 0 || i+2 >= len(input.Field) {
		return "", fmt.Errorf("field must be Class::member (e.g. Player::health), got %q", input.Field)
	}
	class, member := input.Field[:i], input.Field[i+2:]
	off, source, owners, err := resolveFieldOffset(input.FilePath, input.PDBPath, input.PDBForce, class, member)
	if err != nil {
		return "", err
	}
	bin, err := xrefOpen(input.FilePath)
	if err != nil {
		return "", err
	}
	mode := map[string]int{"x86": 32, "x64": 64}[bin.arch]
	if mode == 0 {
		return "", fmt.Errorf("field xref decodes x86/x64 code; this binary is %s. Use xref with target_va for data addresses", bin.arch)
	}
	limit := input.MaxResults
	if limit <= 0 {
		limit = defaultXrefFieldFuncs
	}
	limit = min(limit, maxXrefFieldFuncs)
	timeout := input.TimeoutSec
	if timeout <= 0 {
		timeout = defaultXrefFieldSecs
	}
	timeout = min(timeout, decompileMaxTimeout)

	loc := newXrefLocator(input.FilePath, input.PDBPath, input.PDBForce)
	if loc == nil {
		return "", fmt.Errorf("cannot build the function table of %s", input.FilePath)
	}
	cands, scope := fieldCandidates(bin, loc, mode, off, owners)

	var sb strings.Builder
	fmt.Fprintf(&sb, "Field %s: offset 0x%x (%s)\n", input.Field, off, source)
	fmt.Fprintf(&sb, "Candidates: %d function(s) with a [reg+0x%x] operand (%s).\n", len(cands), off, scope)
	if len(cands) == 0 {
		sb.WriteString("No instruction addresses that offset. The field may be reached through a pointer to a sub-object, an inlined copy, or code xref cannot decode.\n")
		return sb.String(), nil
	}
	todo := cands
	if len(todo) > limit {
		todo = todo[:limit]
	}

	// Decompile the candidates on the pooled worker (the binary stays loaded
	// between batches) and look for the member's name in the C.
	re := regexp.MustCompile(`(->|\.)` + regexp.QuoteMeta(member) + `\b`)
	confirmed := map[uint64][]string{}
	decompiled := map[uint64]bool{}
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	var failure string
	for from := 0; from < len(todo) && failure == ""; from += decompileMaxTargets {
		batch := todo[from:min(from+decompileMaxTargets, len(todo))]
		targets := make([]string, len(batch))
		for k, c := range batch {
			targets[k] = fmt.Sprintf("0x%x", c.start)
		}
		left := time.Until(deadline)
		if left <= 0 {
			failure = "time budget (timeout_sec) used up"
			break
		}
		lines, fail := runDecompileWorker(ctx, decompileRequest{Path: input.FilePath, Targets: targets,
			MemLimitMB: decompileMemLimitMB, PDBPath: input.PDBPath, PDBForce: input.PDBForce}, left)
		for _, l := range lines {
			if l.Kind != "result" || l.C == "" {
				continue
			}
			decompiled[l.Entry] = true
			for _, cl := range strings.Split(l.C, "\n") {
				if re.MatchString(cl) && len(confirmed[l.Entry]) < 3 {
					confirmed[l.Entry] = append(confirmed[l.Entry], strings.TrimSpace(cl))
				}
			}
		}
		failure = fail
	}

	var hit, offsetOnly, notDone []fieldCandidate
	for _, c := range todo {
		switch {
		case len(confirmed[c.start]) > 0:
			hit = append(hit, c)
		case decompiled[c.start]:
			offsetOnly = append(offsetOnly, c)
		default:
			notDone = append(notDone, c)
		}
	}
	fmt.Fprintf(&sb, "\nAccesses confirmed in decompiled C (%d function(s)):\n", len(hit))
	for _, c := range hit {
		fmt.Fprintf(&sb, "  %s @ 0x%x\n", c.name, c.start)
		for _, l := range confirmed[c.start] {
			fmt.Fprintf(&sb, "      %s\n", l)
		}
	}
	if len(offsetOnly) > 0 {
		fmt.Fprintf(&sb, "\nOffset match only (%d): the decompiled C does not name the member -- another type at the same offset, or code without debug types:\n", len(offsetOnly))
		for _, c := range offsetOnly {
			fmt.Fprintf(&sb, "  %s @ 0x%x: %s\n", c.name, c.start, c.first)
		}
	}
	if len(notDone) > 0 || len(cands) > len(todo) {
		fmt.Fprintf(&sb, "\nNot decompiled: %d candidate(s)", len(notDone)+len(cands)-len(todo))
		if failure != "" {
			fmt.Fprintf(&sb, " (%s)", failure)
		}
		fmt.Fprintf(&sb, "; raise max_results (functions, max %d) or timeout_sec.\n", maxXrefFieldFuncs)
		for _, c := range notDone {
			fmt.Fprintf(&sb, "  %s @ 0x%x: %s\n", c.name, c.start, c.first)
		}
	}
	return sb.String(), nil
}

type fieldCandidate struct {
	start  uint64
	name   string
	first  string // first matching instruction, "0x...: asm"
	hits   int
	method bool
}

// fieldCandidates groups the instructions addressing [reg+off] by function.
func fieldCandidates(bin *xrefBinary, loc *xrefLocator, mode int, off int64, owners []string) ([]fieldCandidate, string) {
	isMethod := func(name string) bool {
		for _, o := range owners {
			if isMethodOf(name, o) {
				return true
			}
		}
		return false
	}
	byFunc := map[uint64]*fieldCandidate{}
	note := func(va uint64, inst x86asm.Inst) {
		name, start := loc.function(va)
		if name == "" {
			return
		}
		c := byFunc[start]
		if c == nil {
			base := name
			if k := strings.LastIndex(base, "+0x"); k > 0 {
				base = base[:k]
			}
			c = &fieldCandidate{start: start, name: base, method: isMethod(base)}
			c.first = fmt.Sprintf("0x%x: %s", va, xrefAsm(inst, va))
			byFunc[start] = c
		}
		c.hits++
	}
	scope := ""
	if off >= 0x80 && off <= 0x7FFFFFFF {
		// disp32: the offset's four bytes sit inside every such instruction.
		var pat [4]byte
		binary.LittleEndian.PutUint32(pat[:], uint32(off))
		for _, sec := range bin.sections {
			for from := 0; ; {
				i := bytes.Index(sec.data[from:], pat[:])
				if i < 0 {
					break
				}
				p := from + i
				from = p + 1
				for k := 1; k <= 9 && p-k >= 0; k++ {
					s := p - k
					inst, err := x86asm.Decode(sec.data[s:], mode)
					if err != nil || s+inst.Len < p+4 || !addressesField(inst, off, mode) {
						continue
					}
					note(bin.imageBase+uint64(sec.rva)+uint64(s), inst)
					break
				}
			}
		}
		scope = "whole binary searched"
	} else {
		// disp8 (and 0): scan the class's own methods only.
		for _, va := range loc.symVAs {
			if !isMethod(loc.symbols[va]) {
				continue
			}
			if name, start := loc.function(va); name == "" || start != va {
				continue
			}
			data, at, ok := bin.codeAt(va)
			if !ok {
				continue
			}
			end := loc.functionEnd(va, len(data)-at)
			for cur := at; cur < at+end; {
				inst, err := x86asm.Decode(data[cur:], mode)
				if err != nil {
					cur++
					continue
				}
				if addressesField(inst, off, mode) {
					note(va+uint64(cur-at), inst)
				}
				cur += inst.Len
			}
		}
		scope = fmt.Sprintf("offset below 0x80: only the methods of %s scanned, a disp8 operand is too common to search the whole binary", strings.Join(owners, ", "))
	}
	out := make([]fieldCandidate, 0, len(byFunc))
	for _, c := range byFunc {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].method != out[j].method {
			return out[i].method
		}
		if out[i].hits != out[j].hits {
			return out[i].hits > out[j].hits
		}
		return out[i].start < out[j].start
	})
	return out, scope
}

// isMethodOf matches C++ (Class::f) and Go (pkg.T.f, pkg.(*T).f) method names.
func isMethodOf(name, class string) bool {
	if strings.HasPrefix(name, class+"::") || strings.HasPrefix(name, class+".") {
		return true
	}
	if i := strings.LastIndexByte(class, '.'); i > 0 {
		return strings.HasPrefix(name, class[:i]+".(*"+class[i+1:]+").")
	}
	return false
}

// addressesField reports a memory operand [reg+off] through a general
// register. Stack and frame accesses are left out: [rsp+off] is a local or an
// argument, as is [ebp+off] in 32-bit frames.
func addressesField(inst x86asm.Inst, off int64, mode int) bool {
	for _, a := range inst.Args {
		m, ok := a.(x86asm.Mem)
		if !ok || m.Disp != off || m.Base == 0 || m.Base == x86asm.RIP || m.Base == x86asm.RSP || m.Base == x86asm.ESP {
			continue
		}
		if mode == 32 && m.Base == x86asm.EBP {
			continue
		}
		return true
	}
	return false
}

// functionEnd returns the byte length of the function starting at va, bounded
// by avail.
func (l *xrefLocator) functionEnd(va uint64, avail int) int {
	if l.pdb != nil {
		if r, ok := l.pdb.procAt(va); ok && r.start == va {
			return min(int(r.end-r.start), avail)
		}
	}
	if fn := findFunc(l.funcs, uint32(va-l.imageBase)); fn != nil && l.imageBase+uint64(fn.begin) == va {
		return min(int(fn.end-fn.begin), avail)
	}
	return min(4096, avail)
}

// resolveFieldOffset finds member in class through the PE's PDB or the
// binary's DWARF, searching base-class sub-objects too.
// owners are the class and the bases down to the one declaring the member.
func resolveFieldOffset(path, pdbPath string, pdbForce bool, class, member string) (int64, string, []string, error) {
	if f, err := pe.Open(path); err == nil {
		defer f.Close()
		if pdbPath == "none" {
			return 0, "", nil, fmt.Errorf("field xref needs the PDB's types; pdb_path=none disables it")
		}
		_, is64 := f.OptionalHeader.(*pe.OptionalHeader64)
		pi, note := openPDBInfo(path, pdbPath, pdbForce, f, peImageBase(f), is64)
		if pi == nil {
			if note == "" {
				note = "no matching PDB found beside the image"
			}
			return 0, "", nil, fmt.Errorf("field xref needs debug types: %s. Pass pdb_path, or use xref with target_va on a global", note)
		}
		ti, ok := pi.types.tt.ByName(class)
		if !ok {
			return 0, "", nil, fmt.Errorf("no class/struct named %q in %s (use the qualified name, e.g. ns::Class)", class, pi.path)
		}
		d := pi.types.desc(ti)
		if d == nil {
			return 0, "", nil, fmt.Errorf("%s has no usable layout in the PDB", class)
		}
		if off, owners, ok := findHostMember(d, member, 0, 0); ok {
			return off, "PDB " + pi.path, append([]string{class}, owners...), nil
		}
		return 0, "", nil, fmt.Errorf("%s has no member %q; members: %s", class, member, memberNames(d))
	}
	f, err := elf.Open(path)
	if err != nil {
		return 0, "", nil, fmt.Errorf("field xref needs a PE with its PDB or an ELF with DWARF")
	}
	defer f.Close()
	dd, err := f.DWARF()
	if err != nil {
		return 0, "", nil, fmt.Errorf("no DWARF in %s; field xref needs debug types", path)
	}
	off, err := dwarfMemberOffset(dd, class, member)
	if err != nil {
		return 0, "", nil, err
	}
	return off, "DWARF", []string{class}, nil
}

// findHostMember finds member in d or, through "super_" base-class fields,
// in its bases. Offsets add up along the way; bases are the base classes
// passed through, down to the one that declares the member.
func findHostMember(d *pcode.HostTypeDesc, member string, base int64, depth int) (int64, []string, bool) {
	if d == nil || depth > 8 {
		return 0, nil, false
	}
	for _, f := range d.Fields {
		if f.Name == member {
			return base + int64(f.Offset), nil, true
		}
	}
	for _, f := range d.Fields {
		if strings.HasPrefix(f.Name, "super_") && f.Type != nil {
			if off, bases, ok := findHostMember(f.Type, member, base+int64(f.Offset), depth+1); ok {
				return off, append([]string{f.Type.Name}, bases...), true
			}
		}
	}
	return 0, nil, false
}

// memberNames lists the members, inherited ones included, for an error.
func memberNames(d *pcode.HostTypeDesc) string {
	var names []string
	var walk func(d *pcode.HostTypeDesc, depth int)
	walk = func(d *pcode.HostTypeDesc, depth int) {
		if d == nil || depth > 8 {
			return
		}
		for _, f := range d.Fields {
			if len(names) >= 40 {
				return
			}
			if strings.HasPrefix(f.Name, "super_") {
				walk(f.Type, depth+1)
				continue
			}
			names = append(names, f.Name)
		}
	}
	walk(d, 0)
	if len(names) >= 40 {
		names = append(names, "...")
	}
	return strings.Join(names, ", ")
}

// dwarfMemberOffset finds class (its last name component; DWARF nests names
// in namespaces) and member, following DW_TAG_inheritance into base classes.
func dwarfMemberOffset(dd *dwarf.Data, class, member string) (int64, error) {
	short := class[strings.LastIndex(class, "::")+2:]
	if !strings.Contains(class, "::") {
		short = class
	}
	r := dd.Reader()
	for {
		e, err := r.Next()
		if err != nil || e == nil {
			return 0, fmt.Errorf("no struct/class %q in the DWARF", class)
		}
		if (e.Tag == dwarf.TagStructType || e.Tag == dwarf.TagClassType || e.Tag == dwarf.TagUnionType) && e.Children {
			if name, _ := e.Val(dwarf.AttrName).(string); name == short {
				if off, ok := dwarfFindMember(dd, e.Offset, member, 0, 0); ok {
					return off, nil
				}
				return 0, fmt.Errorf("%s has no member %q in the DWARF", class, member)
			}
		}
	}
}

func dwarfFindMember(dd *dwarf.Data, at dwarf.Offset, member string, base int64, depth int) (int64, bool) {
	if depth > 8 {
		return 0, false
	}
	r := dd.Reader()
	r.Seek(at)
	if _, err := r.Next(); err != nil {
		return 0, false
	}
	var bases []struct {
		typ dwarf.Offset
		off int64
	}
	for {
		e, err := r.Next()
		if err != nil || e == nil || e.Tag == 0 {
			break
		}
		loc, _ := e.Val(dwarf.AttrDataMemberLoc).(int64)
		switch e.Tag {
		case dwarf.TagMember:
			if name, _ := e.Val(dwarf.AttrName).(string); name == member {
				return base + loc, true
			}
		case dwarf.TagInheritance:
			if t, ok := e.Val(dwarf.AttrType).(dwarf.Offset); ok {
				bases = append(bases, struct {
					typ dwarf.Offset
					off int64
				}{t, loc})
			}
		}
		if e.Children {
			r.SkipChildren()
		}
	}
	for _, b := range bases {
		if off, ok := dwarfFindMember(dd, b.typ, member, base+b.off, depth+1); ok {
			return off, true
		}
	}
	return 0, false
}
