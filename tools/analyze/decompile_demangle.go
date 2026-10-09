package analyze

import (
	"fmt"
	"strings"

	"github.com/knewstimek/gopdb"
	"github.com/knewstimek/gopdb/demangle"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// demangledName is the name Ghidra shows for a decorated public: the
// qualified name, with a thunk's this adjustment.
func demangledName(sym *demangle.Symbol) string {
	n := sym.QualifiedName()
	if sym.Func != nil && sym.Func.Thunk {
		n += fmt.Sprintf("`adjustor{%d}'", sym.Func.Adjustor)
	}
	return n
}

// demangledPrototype is the locked prototype a decorated name spells out:
// what Ghidra applies to a function whose module has no private debug
// info. nil when a by-value type cannot be described.
func (c *pdbTypes) demangledPrototype(sym *demangle.Symbol) *pcode.HostFunction {
	f := sym.Func
	if f == nil {
		return nil
	}
	hasThis := f.Member && !f.Static
	hf := &pcode.HostFunction{Model: c.demangledModel(f.CallConv, hasThis), ExtraPop: pcode.ExtrapopUnknown,
		InputLocked: true, Dotdotdot: f.Variadic}
	hf.ModelLock = hf.Model != ""
	if hasThis {
		var cls *pcode.HostTypeDesc
		if len(sym.Name) > 1 {
			cls = c.namedDesc(strings.Join(sym.Name[:len(sym.Name)-1], "::"))
		}
		t := pcode.ResolveHostType(&pcode.HostTypeDesc{Meta: "ptr", Size: c.ptrSize, Elem: cls})
		hf.Params = append(hf.Params, pcode.HostParam{Name: "this", Type: t, Size: t.Size(), ThisPtr: true, NameLock: true})
	}
	for i, p := range f.Params {
		d := c.demangledDesc(p)
		if d == nil || d.Meta == "void" {
			return nil
		}
		t := pcode.ResolveHostType(d)
		if t == nil {
			return nil
		}
		hf.Params = append(hf.Params, pcode.HostParam{Type: t, Size: t.Size(), Name: fmt.Sprintf("param_%d", i+1)})
	}
	// Constructors and destructors spell no return type: leave it to the
	// core rather than lock a wrong one.
	if f.Return != nil {
		if d := c.demangledDesc(f.Return); d != nil {
			if t := pcode.ResolveHostType(d); t != nil {
				hf.Output, hf.OutputLocked = &pcode.HostParam{Type: t, Size: t.Size()}, true
			}
		}
	}
	return hf
}

func (c *pdbTypes) demangledModel(cc string, hasThis bool) string {
	if c.is64 {
		if hasThis {
			return "__thiscall"
		}
		return "__fastcall"
	}
	switch cc {
	case "__cdecl", "__stdcall", "__fastcall", "__thiscall":
		return cc
	}
	return ""
}

// demangledSimple maps undname's primitive spellings to Ghidra's names.
var demangledSimple = map[string]pdb.TypeIndex{
	"char": 0x70, "signed char": 0x10, "unsigned char": 0x20, "__int8": 0x68, "unsigned __int8": 0x69,
	"char8_t": 0x7c, "wchar_t": 0x71, "char16_t": 0x7a, "char32_t": 0x7b,
	"short": 0x11, "unsigned short": 0x21, "__int16": 0x72, "unsigned __int16": 0x73,
	"long": 0x12, "unsigned long": 0x22, "int": 0x74, "unsigned int": 0x75, "__int32": 0x74, "unsigned __int32": 0x75,
	"__int64": 0x13, "unsigned __int64": 0x23, "__int128": 0x14, "unsigned __int128": 0x24,
	"float": 0x40, "double": 0x41, "long double": 0x41, "bool": 0x30, "void": 0x03,
}

// demangledDesc describes a demangled type through the PDB's own type
// records where the type is named, so a demangled prototype carries the
// same structures a full-debug-info one would.
func (c *pdbTypes) demangledDesc(t *demangle.Type) *pcode.HostTypeDesc {
	switch t.Kind {
	case demangle.TypePrimitive:
		if ti, ok := demangledSimple[t.Name]; ok {
			return c.desc(ti)
		}
	case demangle.TypeNullptr:
		return &pcode.HostTypeDesc{Meta: "ptr", Size: c.ptrSize, Elem: &pcode.HostTypeDesc{Meta: "void"}}
	case demangle.TypePointer, demangle.TypeReference, demangle.TypeRValueReference:
		size := c.ptrSize
		if c.is64 && !t.Ptr64 {
			size = 4 // a __ptr32 inside a 64-bit program
		}
		var elem *pcode.HostTypeDesc
		if t.Pointee != nil {
			elem = c.demangledDesc(t.Pointee)
		}
		return &pcode.HostTypeDesc{Meta: "ptr", Size: size, Elem: elem}
	case demangle.TypeNamed:
		return c.namedDesc(t.Name)
	case demangle.TypeArray:
		el := c.demangledDesc(t.Pointee)
		if el == nil || el.Size <= 0 || len(t.Dims) == 0 {
			return nil
		}
		d := el
		for i := len(t.Dims) - 1; i >= 0; i-- {
			n := t.Dims[i]
			d = &pcode.HostTypeDesc{Meta: "array", Size: d.Size * int32(n), Count: int32(n), Elem: d}
		}
		return d
	case demangle.TypeFunction:
		f := t.Func
		cp := &pcode.HostCodeProto{Model: c.demangledModel(f.CallConv, false), InputLocked: true, OutLocked: true, Dotdotdot: f.Variadic}
		parts := []string{"void"}
		if f.Return != nil {
			if r := c.demangledDesc(f.Return); r != nil && r.Meta != "void" {
				cp.Ret = r
				parts[0] = descName(r)
			}
		}
		for _, p := range f.Params {
			pd := c.demangledDesc(p)
			if pd == nil || pd.Meta == "void" {
				return &pcode.HostTypeDesc{Meta: "code", Size: 1}
			}
			cp.Params = append(cp.Params, pd)
			parts = append(parts, descName(pd))
		}
		return &pcode.HostTypeDesc{Meta: "code", Size: 1, Name: "_func_" + strings.Join(parts, "_"), Proto: cp}
	}
	return nil
}

// namedDesc finds a class, struct, union or enum in the PDB by the name a
// demangled type spells. The type table writes template arguments without
// tags ("TArray<FString,FDefaultAllocator>") where undname writes "class
// FString"; both are compared in a normalized form.
func (c *pdbTypes) namedDesc(name string) *pcode.HostTypeDesc {
	if ti, ok := c.tt.ByName(name); ok {
		return c.desc(ti)
	}
	if c.byNorm == nil {
		c.byNorm = map[string]pdb.TypeIndex{}
		for i := 0; i < c.tt.Len(); i++ {
			ti := c.tt.Begin + pdb.TypeIndex(i)
			l, _, _ := c.tt.Raw(ti)
			switch l {
			case pdb.LFClass, pdb.LFStructure, pdb.LFInterface, pdb.LFUnion, pdb.LFEnum,
				pdb.LFClass2, pdb.LFStructure2, pdb.LFUnion2, pdb.LFInterface2:
			default:
				continue
			}
			typ, err := c.tt.Lookup(ti)
			if err != nil {
				continue
			}
			var n string
			switch v := typ.(type) {
			case *pdb.Class:
				if v.FwdRef() {
					continue
				}
				n = v.Name
			case *pdb.Union:
				if v.FwdRef() {
					continue
				}
				n = v.Name
			case *pdb.Enum:
				if v.FwdRef() {
					continue
				}
				n = v.Name
			}
			if k := normTypeName(n); k != "" {
				if _, dup := c.byNorm[k]; !dup {
					c.byNorm[k] = ti
				}
			}
		}
	}
	if ti, ok := c.byNorm[normTypeName(name)]; ok {
		return c.desc(ti)
	}
	return nil
}

var tagWords = strings.NewReplacer("class ", "", "struct ", "", "union ", "", "enum ", "", " __ptr64", "", " ", "")

func normTypeName(n string) string { return tagWords.Replace(n) }
