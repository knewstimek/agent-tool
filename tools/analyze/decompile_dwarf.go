package analyze

import (
	"debug/dwarf"
	"fmt"
	"sort"
	"strings"

	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// dwarfInfo is the decompile host's view of DWARF debug information (ELF,
// and PE images built by MinGW or Go): function names, prototypes and
// locals, global variables, and the types they use.
type dwarfInfo struct {
	src     string // what carried it, for the output header
	d       *dwarf.Data
	ptrSize int32
	funcs   map[uint64]*dwarfFunc
	data    []dwarfVar // globals, sorted by address
	descs   map[dwarf.Type]*pcode.HostTypeDesc
	done    map[dwarf.Type]bool
	types   map[dwarf.Type]pcode.Datatype
	anon    int
}

type dwarfFunc struct {
	name     string
	ret      dwarf.Type // nil for void
	params   []dwarfParam
	variadic bool
	noReturn bool
	locals   map[int64]string
	proto    *pcode.HostFunction
	built    bool
}

type dwarfParam struct {
	name string
	typ  dwarf.Type
}

type dwarfVar struct {
	va   uint64
	name string
	typ  dwarf.Type
	size uint64
}

// DWARF expression opcodes used for locations.
const (
	dwOpAddr          = 0x03
	dwOpFbreg         = 0x91
	dwOpCallFrameCFA  = 0x9c
	dwAttrNoreturnTag = dwarf.Attr(0x87) // DW_AT_noreturn
)

// loadDWARFInfo reads the subprograms and global variables of d. Locals are
// kept only where the frame base is the call frame address (CFA), the entry
// stack pointer plus the return address: then an fbreg offset translates
// directly to the decompiler's entry-relative stack space.
func loadDWARFInfo(src string, d *dwarf.Data, ptrSize int32) *dwarfInfo {
	di := &dwarfInfo{src: src, d: d, ptrSize: ptrSize, funcs: map[uint64]*dwarfFunc{},
		descs: map[dwarf.Type]*pcode.HostTypeDesc{}, done: map[dwarf.Type]bool{}, types: map[dwarf.Type]pcode.Datatype{}}
	r := d.Reader()
	type scope struct {
		name string
		fn   *dwarfFunc
		cfa  bool
	}
	var stack []scope // one per entry with children
	qualify := func(name string) string {
		var parts []string
		for _, s := range stack {
			if s.name != "" && s.fn == nil {
				parts = append(parts, s.name)
			}
		}
		return strings.Join(append(parts, name), "::")
	}
	current := func() (*dwarfFunc, bool) {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].fn != nil {
				return stack[i].fn, stack[i].cfa
			}
		}
		return nil, false
	}
	for {
		e, err := r.Next()
		if err != nil || e == nil {
			break
		}
		if e.Tag == 0 { // end of a children list
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		var sc scope
		switch e.Tag {
		case dwarf.TagCompileUnit:
			stack = stack[:0]
		case dwarf.TagNamespace, dwarf.TagClassType, dwarf.TagStructType, dwarf.TagUnionType:
			sc.name, _ = e.Val(dwarf.AttrName).(string)
		case dwarf.TagInlinedSubroutine:
			// The inlined callee's parameters and variables are not the
			// enclosing function's: collect them into a scope that is dropped.
			sc.fn = &dwarfFunc{}
		case dwarf.TagSubprogram:
			if fn, va, cfa := di.subprogram(e, qualify); fn != nil {
				if _, dup := di.funcs[va]; !dup {
					di.funcs[va] = fn
				}
				sc.fn, sc.cfa = fn, cfa
			}
		case dwarf.TagFormalParameter:
			if fn, _ := current(); fn != nil && len(stack) > 0 && stack[len(stack)-1].fn == fn {
				name, _ := e.Val(dwarf.AttrName).(string)
				t, _ := di.typeOf(e)
				// Go records results as parameters flagged
				// DW_AT_variable_parameter ("~r0"); the first is the return.
				if out, _ := e.Val(dwarf.AttrVarParam).(bool); out {
					if fn.ret == nil {
						fn.ret = t
					}
					break
				}
				fn.params = append(fn.params, dwarfParam{name: name, typ: t})
			}
		case dwarf.TagUnspecifiedParameters:
			if fn, _ := current(); fn != nil {
				fn.variadic = true
			}
		case dwarf.TagVariable:
			name, _ := e.Val(dwarf.AttrName).(string)
			loc, _ := e.Val(dwarf.AttrLocation).([]byte)
			if name == "" || len(loc) == 0 {
				break
			}
			if fn, cfa := current(); fn != nil {
				if cfa && loc[0] == dwOpFbreg {
					if off, n := sleb128(loc[1:]); n > 0 {
						if stackOff := off + int64(di.ptrSize); stackOff < 0 {
							if fn.locals == nil {
								fn.locals = map[int64]string{}
							}
							if _, dup := fn.locals[stackOff]; !dup {
								fn.locals[stackOff] = name
							}
						}
					}
				}
			} else if loc[0] == dwOpAddr && len(loc) >= 1+int(ptrSize) {
				var va uint64
				for i := int(ptrSize); i >= 1; i-- {
					va = va<<8 | uint64(loc[i])
				}
				if t, ok := di.typeOf(e); ok && t.Size() > 0 {
					di.data = append(di.data, dwarfVar{va: va, name: qualify(name), typ: t, size: uint64(t.Size())})
				}
			}
		}
		if e.Children {
			stack = append(stack, sc)
		}
	}
	sort.Slice(di.data, func(i, j int) bool { return di.data[i].va < di.data[j].va })
	return di
}

func (di *dwarfInfo) subprogram(e *dwarf.Entry, qualify func(string) string) (*dwarfFunc, uint64, bool) {
	low, ok := e.Val(dwarf.AttrLowpc).(uint64)
	if !ok {
		return nil, 0, false
	}
	name, _ := e.Val(dwarf.AttrName).(string)
	spec := e
	// A definition outside its class refers to the declaration for the name.
	for i := 0; name == "" && i < 4; i++ {
		off, ok := spec.Val(dwarf.AttrSpecification).(dwarf.Offset)
		if !ok {
			off, ok = spec.Val(dwarf.AttrAbstractOrigin).(dwarf.Offset)
		}
		if !ok {
			break
		}
		r := di.d.Reader()
		r.Seek(off)
		if spec, _ = r.Next(); spec == nil {
			break
		}
		name, _ = spec.Val(dwarf.AttrName).(string)
	}
	if name == "" {
		return nil, 0, false
	}
	fn := &dwarfFunc{name: qualify(name)}
	if nr, _ := e.Val(dwAttrNoreturnTag).(bool); nr {
		fn.noReturn = true
	}
	fn.ret, _ = di.typeOf(e)
	fb, _ := e.Val(dwarf.AttrFrameBase).([]byte)
	return fn, low, len(fb) == 1 && fb[0] == dwOpCallFrameCFA
}

func (di *dwarfInfo) typeOf(e *dwarf.Entry) (dwarf.Type, bool) {
	off, ok := e.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return nil, false
	}
	t, err := di.d.Type(off)
	return t, err == nil
}

func sleb128(b []byte) (int64, int) {
	var v int64
	var shift uint
	for i, c := range b {
		v |= int64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			if shift < 64 && c&0x40 != 0 {
				v |= -1 << shift
			}
			return v, i + 1
		}
		if shift >= 64 {
			break
		}
	}
	return 0, 0
}

func (di *dwarfInfo) kind() string { return "DWARF" }
func (di *dwarfInfo) file() string { return di.src }

func (di *dwarfInfo) functionNames() map[uint64]string {
	out := make(map[uint64]string, len(di.funcs))
	for va, f := range di.funcs {
		out[va] = f.name
	}
	return out
}

func (di *dwarfInfo) noReturn() []uint64 {
	var out []uint64
	for va, f := range di.funcs {
		if f.noReturn {
			out = append(out, va)
		}
	}
	return out
}

func (di *dwarfInfo) localNames(va uint64, _ bool) map[int64]string {
	if !pdbLocalNames {
		return nil
	}
	if f := di.funcs[va]; f != nil {
		return f.locals
	}
	return nil
}

func (di *dwarfInfo) dataAt(va uint64) (string, uint64, pcode.Datatype, bool) {
	i := sort.Search(len(di.data), func(i int) bool { return di.data[i].va > va })
	if i == 0 {
		return "", 0, nil, false
	}
	v := di.data[i-1]
	if va >= v.va+v.size {
		return "", 0, nil, false
	}
	t := di.datatype(v.typ)
	return v.name, v.va, t, t != nil
}

// prototype is the function's locked prototype: types and names from
// DWARF, storage from the compiler spec's default model.
func (di *dwarfInfo) prototype(va uint64) *pcode.HostFunction {
	f := di.funcs[va]
	if f == nil {
		return nil
	}
	if f.built {
		return f.proto
	}
	f.built = true
	hf := &pcode.HostFunction{ExtraPop: pcode.ExtrapopUnknown, InputLocked: true, OutputLocked: true,
		Dotdotdot: f.variadic, NoReturn: f.noReturn}
	for i, p := range f.params {
		t := di.datatype(p.typ)
		if t == nil || t.Metatype() == pcode.TYPE_VOID {
			return nil
		}
		hp := pcode.HostParam{Type: t, Size: t.Size(), Name: fmt.Sprintf("param_%d", i+1)}
		if p.name != "" && pdbParamNames {
			hp.Name, hp.NameLock = p.name, true
		}
		hf.Params = append(hf.Params, hp)
	}
	if f.ret == nil {
		hf.Output = &pcode.HostParam{Type: pcode.ResolveHostType(&pcode.HostTypeDesc{Meta: "void"})}
	} else if rt := di.datatype(f.ret); rt != nil {
		hf.Output = &pcode.HostParam{Type: rt, Size: rt.Size()}
	} else {
		hf.OutputLocked = false
	}
	f.proto = hf
	return hf
}

func (di *dwarfInfo) datatype(t dwarf.Type) pcode.Datatype {
	if t == nil {
		return nil
	}
	if dt, ok := di.types[t]; ok {
		return dt
	}
	dt := pcode.ResolveHostType(di.desc(t))
	di.types[t] = dt
	return dt
}

// baseName is Ghidra's name for a C base type of the given class and size.
func baseName(kind string, size int64) string {
	switch kind {
	case "int":
		return map[int64]string{1: "char", 2: "short", 4: "int", 8: "long", 16: "int16"}[size]
	case "uint":
		return map[int64]string{1: "uchar", 2: "ushort", 4: "uint", 8: "ulong", 16: "uint16"}[size]
	case "float":
		return map[int64]string{4: "float", 8: "double", 10: "float10", 16: "float10"}[size]
	}
	return ""
}

func (di *dwarfInfo) desc(t dwarf.Type) *pcode.HostTypeDesc {
	if t == nil {
		return nil
	}
	if di.done[t] {
		return di.descs[t]
	}
	di.done[t] = true
	d := di.build(t)
	di.descs[t] = d
	return d
}

func (di *dwarfInfo) build(t dwarf.Type) *pcode.HostTypeDesc {
	size := int32(t.Size())
	switch v := t.(type) {
	case *dwarf.VoidType:
		return &pcode.HostTypeDesc{Meta: "void"}
	case *dwarf.BoolType:
		return &pcode.HostTypeDesc{Meta: "bool", Name: "bool", Size: size}
	case *dwarf.CharType:
		return &pcode.HostTypeDesc{Meta: "int", Name: "char", Size: size, Char: size == 1, Utf: size > 1}
	case *dwarf.UcharType:
		return &pcode.HostTypeDesc{Meta: "uint", Name: "uchar", Size: size, Char: size == 1, Utf: size > 1}
	case *dwarf.IntType:
		if n := baseName("int", int64(size)); n != "" {
			return &pcode.HostTypeDesc{Meta: "int", Name: n, Size: size}
		}
	case *dwarf.UintType, *dwarf.AddrType:
		if n := baseName("uint", int64(size)); n != "" {
			return &pcode.HostTypeDesc{Meta: "uint", Name: n, Size: size}
		}
	case *dwarf.FloatType:
		if n := baseName("float", int64(size)); n != "" {
			return &pcode.HostTypeDesc{Meta: "float", Name: n, Size: size}
		}
	case *dwarf.QualType:
		return di.desc(v.Type)
	case *dwarf.TypedefType:
		under := di.desc(v.Type)
		if under == nil || v.Name == "" {
			return under
		}
		switch under.Meta {
		case "struct", "union", "array", "code":
			// A copy carrying the typedef name could be resolved before the
			// structure's members are filled in (recursive types) and fix an
			// empty layout under its id; such types print by their own name.
			return under
		}
		td := *under
		td.Typedef = ghidraName(v.Name)
		return &td
	case *dwarf.PtrType:
		ps := size
		if ps <= 0 {
			ps = di.ptrSize
		}
		// Registered before the target: a member may use this pointer type.
		d := &pcode.HostTypeDesc{Meta: "ptr", Size: ps}
		di.descs[t] = d
		d.Elem = di.desc(v.Type)
		return d
	case *dwarf.ArrayType:
		el := di.desc(v.Type)
		if el == nil || v.Count <= 0 || el.Size <= 0 {
			return nil
		}
		return &pcode.HostTypeDesc{Meta: "array", Size: el.Size * int32(v.Count), Count: int32(v.Count), Elem: el}
	case *dwarf.EnumType:
		meta := "enum_int"
		vals := map[uint64]string{}
		mask := ^uint64(0)
		if size > 0 && size < 8 {
			mask = 1<<(8*uint(size)) - 1
		}
		for _, e := range v.Val {
			if _, dup := vals[uint64(e.Val)&mask]; !dup {
				vals[uint64(e.Val)&mask] = e.Name
			}
		}
		return &pcode.HostTypeDesc{Meta: meta, Name: di.typeName(v.EnumName), Size: size, EnumValues: vals}
	case *dwarf.StructType:
		if v.Incomplete || size <= 0 {
			return nil
		}
		meta := "struct"
		if v.Kind == "union" {
			meta = "union"
		}
		d := &pcode.HostTypeDesc{Meta: meta, Name: di.typeName(v.StructName), Size: size}
		if meta == "struct" {
			d.ID = fmt.Sprintf("dwarf:%p", v)
		}
		di.descs[t] = d
		end := int64(0)
		for _, f := range v.Field {
			if f.BitSize > 0 || f.Type == nil {
				continue // bitfields are not expressible
			}
			fd := di.desc(f.Type)
			if fd == nil || fd.Size <= 0 {
				continue
			}
			if meta == "struct" && (f.ByteOffset < end || f.ByteOffset+int64(fd.Size) > int64(size)) {
				continue
			}
			d.Fields = append(d.Fields, pcode.HostFieldDesc{Name: f.Name, Offset: int32(f.ByteOffset), Type: fd})
			if meta == "struct" {
				end = f.ByteOffset + int64(fd.Size)
			}
		}
		return d
	case *dwarf.FuncType:
		cp := &pcode.HostCodeProto{InputLocked: true, OutLocked: true}
		parts := []string{"void"}
		if v.ReturnType != nil {
			if r := di.desc(v.ReturnType); r != nil && r.Meta != "void" {
				cp.Ret = r
				parts[0] = descName(r)
			}
		}
		for _, p := range v.ParamType {
			if _, dots := p.(*dwarf.DotDotDotType); dots {
				cp.Dotdotdot = true
				continue
			}
			pd := di.desc(p)
			if pd == nil || pd.Meta == "void" {
				return &pcode.HostTypeDesc{Meta: "code", Size: 1, Name: "code"}
			}
			cp.Params = append(cp.Params, pd)
			parts = append(parts, descName(pd))
		}
		return &pcode.HostTypeDesc{Meta: "code", Size: 1, Name: "_func_" + strings.Join(parts, "_"), Proto: cp}
	}
	return nil
}

func (di *dwarfInfo) typeName(n string) string {
	if n == "" {
		di.anon++
		return fmt.Sprintf("anon_%d", di.anon)
	}
	return typeName(n)
}
