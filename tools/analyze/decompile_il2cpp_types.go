package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/knewstimek/gosleigh/pkg/pcode"
)

type il2cppLayout struct{ size, align int32 }

// Only plain C layouts emitted by the dumper are accepted. Unknown packing,
// inheritance, unions, bitfields and recursive value layouts stay unknown.
type il2cppTypes struct {
	bodies  map[string]string
	aliases map[string]string
	layouts map[string]il2cppLayout
	busy    map[string]bool
}

var (
	il2cppIdent   = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9]*$`)
	il2cppStruct  = regexp.MustCompile(`(?s)\bstruct\s+([A-Za-z_][A-Za-z_0-9]*)\s*\{([^{}]*)\}\s*;`)
	il2cppTypedef = regexp.MustCompile(`\btypedef\s+([^;{}()]+?)\s+([A-Za-z_][A-Za-z_0-9]*)\s*;`)
	il2cppComment = regexp.MustCompile(`(?s)/\*.*?\*/|//[^\r\n]*`)
	il2cppPacking = regexp.MustCompile(`#\s*pragma\s+pack\b`)
	il2cppAlign   = regexp.MustCompile(`\b(?:__attribute__|__declspec|alignas|_Alignas)\b`)
	il2cppField   = regexp.MustCompile(`^(.+?[\s*])([A-Za-z_][A-Za-z_0-9]*)(?:\s*\[\s*([0-9]+)\s*\])?$`)
)

func loadIL2CPPTypes(script string) (*il2cppTypes, error) {
	path := filepath.Join(filepath.Dir(script), "il2cpp.h")
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return newIL2CPPTypes(""), nil
	}
	if err != nil {
		return nil, fmt.Errorf("il2cpp.h: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > 128<<20 {
		return nil, fmt.Errorf("il2cpp.h must be a regular file of at most 128 MiB")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("il2cpp.h: %w", err)
	}
	return newIL2CPPTypes(string(data)), nil
}

func newIL2CPPTypes(header string) *il2cppTypes {
	t := &il2cppTypes{bodies: map[string]string{}, aliases: map[string]string{}, layouts: map[string]il2cppLayout{}, busy: map[string]bool{}}
	header = il2cppComment.ReplaceAllString(header, " ")
	// Do not guess the active packing state of arbitrary C preprocessor input.
	if il2cppPacking.MatchString(header) || il2cppAlign.MatchString(header) {
		return t
	}
	for _, m := range il2cppStruct.FindAllStringSubmatch(header, -1) {
		if old, exists := t.bodies[m[1]]; exists && old != m[2] {
			t.bodies[m[1]] = "" // conflicting declarations cannot regain a layout
		} else if !exists {
			t.bodies[m[1]] = m[2]
		}
	}
	for _, m := range il2cppTypedef.FindAllStringSubmatch(header, -1) {
		if old, exists := t.aliases[m[2]]; exists && old != m[1] {
			t.aliases[m[2]] = ""
		} else if !exists {
			t.aliases[m[2]] = m[1]
		}
	}
	return t
}

func il2cppBaseType(s string) string {
	var words []string
	for _, w := range strings.Fields(s) {
		switch w {
		case "const", "volatile", "struct":
		default:
			words = append(words, w)
		}
	}
	return strings.Join(words, " ")
}

func il2cppPrimitive(name string) *pcode.HostTypeDesc {
	meta, size := "", int32(0)
	switch name {
	case "void":
		meta = "void"
	case "bool", "_Bool", "Il2CppBoolean":
		meta, size = "bool", 1
	case "char", "signed char", "int8_t", "__int8":
		meta, size = "int", 1
	case "unsigned char", "uint8_t":
		meta, size = "uint", 1
	case "short", "short int", "signed short", "int16_t", "__int16":
		meta, size = "int", 2
	case "unsigned short", "unsigned short int", "uint16_t", "char16_t", "Il2CppChar":
		meta, size = "uint", 2
	case "int", "signed int", "long", "long int", "int32_t", "__int32":
		meta, size = "int", 4
	case "unsigned int", "unsigned", "unsigned long", "unsigned long int", "uint32_t":
		meta, size = "uint", 4
	case "long long", "long long int", "int64_t", "__int64", "intptr_t":
		meta, size = "int", 8
	case "unsigned long long", "unsigned long long int", "unsigned __int64", "uint64_t", "uintptr_t", "size_t":
		meta, size = "uint", 8
	case "float":
		meta, size = "float", 4
	case "double":
		meta, size = "float", 8
	default:
		return nil
	}
	return &pcode.HostTypeDesc{Meta: meta, Size: size}
}

// ctype returns the storage type and whether it is a value aggregate. No
// unknown identifier is treated as a pointer unless C actually spells '*'.
func (t *il2cppTypes) ctype(raw string) (*pcode.HostTypeDesc, bool) {
	if strings.ContainsAny(raw, "()[]{}:,;&=\r\n") {
		return nil, false
	}
	if strings.Contains(raw, "*") {
		if strings.Count(raw, "*") > 16 {
			return nil, false
		}
		base := il2cppBaseType(strings.ReplaceAll(raw, "*", " "))
		if !il2cppIdent.MatchString(base) && il2cppPrimitive(base) == nil {
			return nil, false
		}
		d := il2cppPrimitive(base)
		if d == nil {
			d = &pcode.HostTypeDesc{Meta: "void"}
		}
		for range strings.Count(raw, "*") {
			d = &pcode.HostTypeDesc{Meta: "ptr", Size: 8, Elem: d}
		}
		return d, false
	}
	name := il2cppBaseType(raw)
	if d := il2cppPrimitive(name); d != nil {
		return d, false
	}
	if !il2cppIdent.MatchString(name) || t.busy[name] || len(t.busy) >= 64 {
		return nil, false
	}
	if alias, ok := t.aliases[name]; ok {
		t.busy[name] = true
		d, aggregate := t.ctype(alias)
		delete(t.busy, name)
		return d, aggregate
	}
	if l, ok := t.layout(name); ok {
		return &pcode.HostTypeDesc{Meta: "struct", Size: l.size}, true
	}
	return nil, false
}

func (t *il2cppTypes) layout(name string) (il2cppLayout, bool) {
	if l, ok := t.layouts[name]; ok {
		return l, l.size > 0
	}
	body, ok := t.bodies[name]
	if !ok || body == "" || t.busy[name] || len(t.busy) >= 64 {
		return il2cppLayout{}, false
	}
	t.busy[name] = true
	defer delete(t.busy, name)
	l := il2cppLayout{align: 1}
	valid := true
	for _, field := range strings.Split(body, ";") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		m := il2cppField.FindStringSubmatch(field)
		if m == nil {
			valid = false
			break
		}
		d, aggregate := t.ctype(m[1])
		if d == nil || d.Size <= 0 {
			valid = false
			break
		}
		align := min(d.Size, int32(8))
		if aggregate {
			align = t.layouts[il2cppBaseType(m[1])].align
			if align == 0 { // an aggregate typedef: resolve its underlying name
				base := il2cppBaseType(m[1])
				for i := 0; i < 64 && t.aliases[base] != ""; i++ {
					base = il2cppBaseType(t.aliases[base])
				}
				align = t.layouts[base].align
			}
		}
		count := int64(1)
		if m[3] != "" {
			count, _ = strconv.ParseInt(m[3], 10, 32)
		}
		if align <= 0 || count <= 0 || count*int64(d.Size) > 1<<20 || int64(l.size)+count*int64(d.Size)+16 > 1<<20 {
			valid = false
			break
		}
		l.size = (l.size + align - 1) / align * align
		l.size += int32(count * int64(d.Size))
		l.align = max(l.align, align)
	}
	if valid && l.size > 0 {
		l.size = (l.size + l.align - 1) / l.align * l.align
	} else {
		l = il2cppLayout{}
	}
	t.layouts[name] = l
	return l, l.size > 0
}
