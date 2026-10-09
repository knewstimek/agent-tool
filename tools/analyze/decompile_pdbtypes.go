package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/knewstimek/gopdb"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// pdbTypes converts PDB (TPI) types into the decompiler's host type
// descriptions, which the core interns into its data-types. Conversion is
// lazy and memoized per type index: a large program's type graph is only
// walked where a decompiled function reaches it.
type pdbTypes struct {
	tt, ids *pdb.TypeTable
	ptrSize int32
	is64    bool
	descs   map[pdb.TypeIndex]*pcode.HostTypeDesc
	done    map[pdb.TypeIndex]bool // descs[ti] computed (may be nil)
	types   map[pdb.TypeIndex]pcode.Datatype
	byNorm  map[string]pdb.TypeIndex // normalized UDT name -> definition, built on first use
}

func newPDBTypes(tt, ids *pdb.TypeTable, is64 bool) *pdbTypes {
	ps := int32(4)
	if is64 {
		ps = 8
	}
	return &pdbTypes{tt: tt, ids: ids, ptrSize: ps, is64: is64,
		descs: map[pdb.TypeIndex]*pcode.HostTypeDesc{}, done: map[pdb.TypeIndex]bool{},
		types: map[pdb.TypeIndex]pcode.Datatype{}}
}

// simpleNames are the names Ghidra gives the C built-in types, which is how
// they print.
var simpleNames = map[uint8]struct {
	name      string
	meta      string
	char, utf bool
}{
	0x70: {"char", "int", true, false}, 0x10: {"char", "int", true, false}, 0x68: {"char", "int", true, false},
	0x20: {"uchar", "uint", true, false}, 0x69: {"uchar", "uint", true, false}, 0x7c: {"char8_t", "uint", true, false},
	0x71: {"wchar_t", "int", false, true}, 0x7a: {"char16_t", "uint", false, true}, 0x7b: {"char32_t", "uint", false, true},
	0x11: {"short", "int", false, false}, 0x72: {"short", "int", false, false},
	0x21: {"ushort", "uint", false, false}, 0x73: {"ushort", "uint", false, false},
	0x12: {"long", "int", false, false}, 0x22: {"ulong", "uint", false, false},
	0x74: {"int", "int", false, false}, 0x75: {"uint", "uint", false, false},
	0x13: {"longlong", "int", false, false}, 0x76: {"longlong", "int", false, false},
	0x23: {"ulonglong", "uint", false, false}, 0x77: {"ulonglong", "uint", false, false},
	0x14: {"int16", "int", false, false}, 0x78: {"int16", "int", false, false},
	0x24: {"uint16", "uint", false, false}, 0x79: {"uint16", "uint", false, false},
	0x40: {"float", "float", false, false}, 0x41: {"double", "float", false, false},
	0x42: {"float10", "float", false, false}, 0x46: {"float2", "float", false, false},
	0x30: {"bool", "bool", false, false}, 0x31: {"bool", "bool", false, false},
	0x32: {"bool", "bool", false, false}, 0x33: {"bool", "bool", false, false},
	0x08: {"HRESULT", "int", false, false},
}

// desc returns the host description of ti, nil when it cannot be expressed
// (the core then treats the storage as undefined bytes).
func (c *pdbTypes) desc(ti pdb.TypeIndex) *pcode.HostTypeDesc {
	// A forward declaration and its definition must share one memo entry:
	// otherwise a member pointing back through the forward declaration
	// (Node *next inside Node) finds it "in progress" with no description.
	if !pdb.IsSimple(ti) {
		ti = c.tt.Resolve(ti)
	}
	if c.done[ti] {
		return c.descs[ti]
	}
	c.done[ti] = true
	d := c.build(ti)
	c.descs[ti] = d
	return d
}

func (c *pdbTypes) build(ti pdb.TypeIndex) *pcode.HostTypeDesc {
	if pdb.IsSimple(ti) {
		st, ok := pdb.Simple(ti)
		if !ok && st.Mode == pdb.SimpleDirect {
			return nil
		}
		var base *pcode.HostTypeDesc
		if st.Class == pdb.SimpleVoid {
			base = &pcode.HostTypeDesc{Meta: "void"}
		} else if n, known := simpleNames[uint8(ti)]; known {
			base = &pcode.HostTypeDesc{Name: n.name, Meta: n.meta, Size: int32(st.Size), Char: n.char, Utf: n.utf}
		}
		if st.Mode == pdb.SimpleDirect {
			return base
		}
		return &pcode.HostTypeDesc{Meta: "ptr", Size: int32(st.PointerSize()), Elem: base}
	}
	typ, err := c.tt.Lookup(ti)
	if err != nil {
		return nil
	}
	switch t := typ.(type) {
	case *pdb.Modifier:
		return c.desc(t.Type)
	case *pdb.Bitfield:
		return c.desc(t.Type)
	case *pdb.Pointer:
		if t.Mode == pdb.PtrModeMemberData || t.Mode == pdb.PtrModeMemberFunc {
			return nil
		}
		size := int32(t.Size)
		if size == 0 {
			size = c.ptrSize
		}
		// References are pointers to the decompiler (as in Ghidra). The
		// pointer is registered before its referent is described: a member of
		// the referent may use this very pointer type (Node *next in Node).
		d := &pcode.HostTypeDesc{Meta: "ptr", Size: size}
		c.descs[ti] = d
		d.Elem = c.desc(t.Referent)
		return d
	case *pdb.Array:
		elem := c.desc(t.Element)
		es := c.size(t.Element)
		if elem == nil || es == 0 || t.Size%es != 0 {
			return nil
		}
		return &pcode.HostTypeDesc{Meta: "array", Size: int32(t.Size), Count: int32(t.Size / es), Elem: elem}
	case *pdb.Class:
		def := c.tt.Resolve(ti)
		if def != ti {
			return c.desc(def)
		}
		if t.FwdRef() || t.Size == 0 {
			return nil
		}
		d := &pcode.HostTypeDesc{Meta: "struct", Name: typeName(t.Name), Size: int32(t.Size), ID: typeID(t.Name, t.UniqueName)}
		// Registered before the members: a member may point back here.
		c.descs[ti] = d
		d.Fields = c.structFields(t.FieldList, int64(t.Size))
		return d
	case *pdb.Union:
		def := c.tt.Resolve(ti)
		if def != ti {
			return c.desc(def)
		}
		if t.FwdRef() || t.Size == 0 {
			return nil
		}
		d := &pcode.HostTypeDesc{Meta: "union", Name: typeName(t.Name), Size: int32(t.Size)}
		c.descs[ti] = d
		fields, _ := c.tt.Fields(t.FieldList)
		for _, f := range fields {
			if m, ok := f.(*pdb.Member); ok {
				if md := c.desc(m.Type); md != nil {
					d.Fields = append(d.Fields, pcode.HostFieldDesc{Name: m.Name, Offset: int32(m.Offset), Type: md})
				}
			}
		}
		return d
	case *pdb.Enum:
		def := c.tt.Resolve(ti)
		if def != ti {
			return c.desc(def)
		}
		under, _ := pdb.Simple(t.Underlying)
		size := int32(under.Size)
		if size == 0 {
			size = 4
		}
		meta := "enum_uint"
		if under.Class == pdb.SimpleSigned || under.Class == pdb.SimpleChar && under.Name != "unsigned char" {
			meta = "enum_int"
		}
		d := &pcode.HostTypeDesc{Meta: meta, Name: typeName(t.Name), Size: size, EnumValues: map[uint64]string{}}
		mask := ^uint64(0)
		if size < 8 {
			mask = 1<<(8*uint(size)) - 1
		}
		fields, _ := c.tt.Fields(t.FieldList)
		for _, f := range fields {
			if e, ok := f.(*pdb.Enumerate); ok {
				if _, dup := d.EnumValues[e.Value&mask]; !dup {
					d.EnumValues[e.Value&mask] = e.Name
				}
			}
		}
		return d
	case *pdb.ProcedureType:
		return c.codeDesc(t.Return, 0, t.ArgList, t.CallConv)
	case *pdb.MemberFunction:
		return c.codeDesc(t.Return, t.This, t.ArgList, t.CallConv)
	}
	return nil
}

// structFields lays out a structure's members. The core's structures cannot
// overlap fields, so a member that overlaps the previous one (a bitfield
// group, an anonymous union's alternatives) is left out; bitfields are not
// expressible at all.
func (c *pdbTypes) structFields(fl pdb.TypeIndex, size int64) []pcode.HostFieldDesc {
	fields, _ := c.tt.Fields(fl)
	var out []pcode.HostFieldDesc
	for _, f := range fields {
		switch m := f.(type) {
		case *pdb.Member:
			if bt, err := c.tt.Lookup(m.Type); err == nil {
				if _, bit := bt.(*pdb.Bitfield); bit {
					continue
				}
			}
			if md := c.desc(m.Type); md != nil {
				out = append(out, pcode.HostFieldDesc{Name: m.Name, Offset: int32(m.Offset), Type: md})
			}
		case *pdb.BaseClass:
			if bd := c.desc(m.Type); bd != nil {
				_, short := splitQualified(bd.Name)
				out = append(out, pcode.HostFieldDesc{Name: "super_" + short, Offset: int32(m.Offset), Type: bd})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	kept := out[:0]
	end := int64(0)
	for _, f := range out {
		fs := int64(c.descSize(f.Type))
		if int64(f.Offset) < end || fs <= 0 || int64(f.Offset)+fs > size {
			continue
		}
		kept = append(kept, f)
		end = int64(f.Offset) + fs
	}
	return kept
}

func (c *pdbTypes) descSize(d *pcode.HostTypeDesc) int32 {
	if d == nil {
		return 0
	}
	return d.Size
}

// codeDesc describes a function type (the pointee of a function pointer).
func (c *pdbTypes) codeDesc(ret, this, args pdb.TypeIndex, cc pdb.CallConv) *pcode.HostTypeDesc {
	cp := &pcode.HostCodeProto{Model: c.model(cc, this != 0), InputLocked: true, OutLocked: true}
	var parts []string
	if r := c.desc(ret); r != nil && r.Meta != "void" {
		cp.Ret = r
		parts = append(parts, descName(r))
	} else {
		parts = append(parts, "void")
	}
	if this != 0 {
		td := c.desc(this)
		if td == nil {
			return &pcode.HostTypeDesc{Meta: "code", Size: 1}
		}
		cp.Params = append(cp.Params, td)
	}
	list, dots := c.argList(args)
	for _, a := range list {
		ad := c.desc(a)
		if ad == nil || ad.Meta == "void" {
			return &pcode.HostTypeDesc{Meta: "code", Size: 1}
		}
		cp.Params = append(cp.Params, ad)
		parts = append(parts, descName(ad))
	}
	cp.Dotdotdot = dots
	// Ghidra names a PDB function type after its signature.
	return &pcode.HostTypeDesc{Meta: "code", Size: 1, Name: "_func_" + strings.Join(parts, "_"), Proto: cp}
}

func descName(d *pcode.HostTypeDesc) string {
	switch {
	case d == nil:
		return "undefined"
	case d.Meta == "ptr":
		return descName(d.Elem) + "_ptr"
	case d.Meta == "array":
		return descName(d.Elem) + "_arr"
	case d.Name != "":
		return d.Name
	}
	return d.Meta
}

// argList returns an argument list's types; a trailing T_NOTYPE marks
// varargs.
func (c *pdbTypes) argList(ti pdb.TypeIndex) ([]pdb.TypeIndex, bool) {
	typ, err := c.tt.Lookup(ti)
	if err != nil {
		return nil, false
	}
	al, ok := typ.(*pdb.ArgList)
	if !ok {
		return nil, false
	}
	args := al.Args
	if n := len(args); n > 0 && args[n-1] == 0 {
		return args[:n-1], true
	}
	return args, false
}

// model is the cspec prototype a PDB calling convention selects. x64 has
// one convention; methods with a this pointer use the __thiscall model,
// which differs from __fastcall in this-pointer handling.
func (c *pdbTypes) model(cc pdb.CallConv, hasThis bool) string {
	if c.is64 {
		if hasThis {
			return "__thiscall"
		}
		return "__fastcall"
	}
	switch cc {
	case pdb.CallNearC:
		return "__cdecl"
	case pdb.CallNearStd:
		return "__stdcall"
	case pdb.CallNearFast:
		return "__fastcall"
	case pdb.CallThis:
		return "__thiscall"
	}
	return ""
}

// size is the byte size of ti (0 when unknown).
func (c *pdbTypes) size(ti pdb.TypeIndex) uint64 {
	if pdb.IsSimple(ti) {
		st, _ := pdb.Simple(ti)
		if p := st.PointerSize(); p > 0 {
			return uint64(p)
		}
		return uint64(st.Size)
	}
	typ, err := c.tt.Lookup(ti)
	if err != nil {
		return 0
	}
	switch t := typ.(type) {
	case *pdb.Modifier:
		return c.size(t.Type)
	case *pdb.Pointer:
		if t.Size != 0 {
			return uint64(t.Size)
		}
		return uint64(c.ptrSize)
	case *pdb.Array:
		return t.Size
	case *pdb.Class:
		if t.FwdRef() {
			if def := c.tt.Resolve(ti); def != ti {
				return c.size(def)
			}
			return 0
		}
		return t.Size
	case *pdb.Union:
		if t.FwdRef() {
			if def := c.tt.Resolve(ti); def != ti {
				return c.size(def)
			}
			return 0
		}
		return t.Size
	case *pdb.Enum:
		return c.size(t.Underlying)
	case *pdb.Bitfield:
		return c.size(t.Type)
	}
	return 0
}

// datatype is the core data-type of ti (nil when not expressible).
func (c *pdbTypes) datatype(ti pdb.TypeIndex) pcode.Datatype {
	if t, ok := c.types[ti]; ok {
		return t
	}
	t := pcode.ResolveHostType(c.desc(ti))
	c.types[ti] = t
	return t
}

// prototype is the locked prototype of a PDB procedure: model from its
// calling convention, the this pointer of a method, parameter types and
// names (from its parameter records), return type and no-return flag. The
// core assigns the storage. nil when a type is not expressible.
func (c *pdbTypes) prototype(p *pdb.Procedure) *pcode.HostFunction {
	ti := p.Type
	if p.TypeIsID() && c.ids != nil {
		id, err := c.ids.Lookup(ti)
		if err != nil {
			return nil
		}
		switch v := id.(type) {
		case *pdb.FuncID:
			ti = v.Type
		case *pdb.MFuncID:
			ti = v.Type
		default:
			return nil
		}
	}
	typ, err := c.tt.Lookup(ti)
	if err != nil {
		return nil
	}
	var ret, this, args pdb.TypeIndex
	var cc pdb.CallConv
	switch t := typ.(type) {
	case *pdb.ProcedureType:
		ret, args, cc = t.Return, t.ArgList, t.CallConv
	case *pdb.MemberFunction:
		ret, this, args, cc = t.Return, t.This, t.ArgList, t.CallConv
	default:
		return nil
	}
	list, dots := c.argList(args)
	n := len(list)
	if this != 0 {
		n++
	}
	var names []string
	if pdbParamNames {
		names = paramNames(p, n)
	}
	hf := &pcode.HostFunction{Model: c.model(cc, this != 0), ModelLock: true, ExtraPop: pcode.ExtrapopUnknown,
		InputLocked: true, OutputLocked: true, Dotdotdot: dots, NoReturn: p.Flags&pdb.ProcNoReturn != 0}
	if hf.Model == "" {
		hf.ModelLock = false
	}
	if this != 0 {
		t := c.datatype(this)
		if t == nil {
			return nil
		}
		hf.Params = append(hf.Params, pcode.HostParam{Name: "this", Type: t, Size: t.Size(), ThisPtr: true, NameLock: true})
		if len(names) > 0 && names[0] == "this" {
			names = names[1:]
		}
	}
	if len(names) != len(list) {
		names = nil // records do not line up with the type: use the core's names
	}
	for i, a := range list {
		t := c.datatype(a)
		if t == nil || t.Metatype() == pcode.TYPE_VOID {
			return nil
		}
		// Unnamed parameters get Ghidra's default names, as its Java host
		// sends them: the core does not invent names for locked inputs.
		hp := pcode.HostParam{Type: t, Size: t.Size(), Name: fmt.Sprintf("param_%d", i+1)}
		if names != nil && names[i] != "" {
			hp.Name, hp.NameLock = names[i], true
		}
		hf.Params = append(hf.Params, hp)
	}
	if rt := c.datatype(ret); rt != nil {
		hf.Output = &pcode.HostParam{Type: rt, Size: rt.Size()}
	} else {
		hf.OutputLocked = false
	}
	return hf
}

// pdbParamNames applies PDB parameter names. Ghidra's analysis does not, so
// the golden measurement turns it off to compare structure alone.
var pdbParamNames = true

// paramNames are a procedure's n parameter names in order: the S_LOCAL
// records flagged as parameters (optimized code). Debug code (/Od) has no
// S_LOCAL; there the compiler emits the parameters' register- or frame-
// relative records first, ahead of the locals.
func paramNames(p *pdb.Procedure, n int) []string {
	var names, rel []string
	for _, s := range p.Locals {
		switch v := s.(type) {
		case *pdb.Local:
			if v.Flags&pdb.LocalIsParam != 0 {
				names = append(names, v.Name)
			}
		case *pdb.RegRel:
			rel = append(rel, v.Name)
		case *pdb.BPRel:
			rel = append(rel, v.Name)
		}
	}
	if len(names) == 0 && len(rel) >= n {
		names = rel[:n]
	}
	return names
}

// typeName is a type's name as Ghidra prints it: its own name without the
// enclosing namespaces, spaces made underscores.
func typeName(qualified string) string {
	_, n := splitQualified(qualified)
	return ghidraName(n)
}

func typeID(name, unique string) string {
	if unique != "" {
		return "pdb:" + unique
	}
	return "pdb:" + name
}
