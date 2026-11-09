package analyze

import (
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type il2cppRuntimeType struct {
	data uint64
	bits uint32
}
type il2cppNativeTypes struct {
	image                *il2cppNativeImage
	metadata             *il2cppNativeMetadata
	registration         il2cppNativeRegistration
	tokens               map[int]string
	names                map[int]string
	primitiveDefinitions map[byte]int
}

func (t *il2cppNativeTypes) runtimePointer(va uint64) (il2cppRuntimeType, bool) {
	d := t.image.read(va, 12)
	if d == nil {
		return il2cppRuntimeType{}, false
	}
	return il2cppRuntimeType{binary.LittleEndian.Uint64(d), binary.LittleEndian.Uint32(d[8:])}, true
}
func (t *il2cppNativeTypes) runtime(index int) (il2cppRuntimeType, bool) {
	if index < 0 || uint64(index) >= t.registration.typesCount {
		return il2cppRuntimeType{}, false
	}
	p, ok := t.image.pointer(t.registration.types + uint64(index)*8)
	if !ok {
		return il2cppRuntimeType{}, false
	}
	return t.runtimePointer(p)
}
func (t *il2cppNativeTypes) definition(r il2cppRuntimeType, depth int) int {
	if depth > 16 {
		return -1
	}
	switch byte(r.bits >> 16) {
	case 0x11, 0x12:
		i := int(int32(r.data))
		if i >= 0 && i < len(t.metadata.types) {
			return i
		}
	case 0x15:
		p, ok := t.image.pointer(r.data)
		if ok {
			if v, ok := t.runtimePointer(p); ok {
				return t.definition(v, depth+1)
			}
		}
	default:
		if t.primitiveDefinitions == nil {
			t.primitiveDefinitions = map[byte]int{}
			known := map[string]byte{"Void": 1, "Boolean": 2, "Char": 3, "SByte": 4, "Byte": 5, "Int16": 6, "UInt16": 7, "Int32": 8, "UInt32": 9, "Int64": 10, "UInt64": 11, "Single": 12, "Double": 13, "String": 14, "TypedReference": 0x16, "IntPtr": 0x18, "UIntPtr": 0x19, "Object": 0x1c}
			for i, td := range t.metadata.types {
				if td.namespace == "System" && td.declaring < 0 {
					if kind, ok := known[td.name]; ok {
						if _, exists := t.primitiveDefinitions[kind]; exists {
							t.primitiveDefinitions[kind] = -1
						} else {
							t.primitiveDefinitions[kind] = i
						}
					}
				}
			}
		}
		if i, ok := t.primitiveDefinitions[byte(r.bits>>16)]; ok {
			return i
		}
	}
	return -1
}
func (t *il2cppNativeTypes) name(index, depth int) string {
	if name := t.names[index]; name != "" {
		return name
	}
	if depth > 32 || index < 0 || index >= len(t.metadata.types) {
		return ""
	}
	r := t.metadata.types[index]
	name := il2cppNativeQualifiedName(r.namespace, r.name)
	if r.declaring >= 0 {
		v, ok := t.runtime(r.declaring)
		if !ok {
			return ""
		}
		parent := t.definition(v, 0)
		if parent < 0 || parent == index {
			return ""
		}
		p := t.name(parent, depth+1)
		if p == "" {
			return ""
		}
		name = p + "/" + r.name
	}
	t.names[index] = name
	return name
}
func (t *il2cppNativeTypes) instanceSize(index int) int {
	if index < 0 || index >= len(t.metadata.types) {
		return 0
	}
	p, ok := t.image.pointer(t.registration.typeSizes + uint64(index)*8)
	if !ok {
		return 0
	}
	d := t.image.read(p, 16)
	if d == nil {
		return 0
	}
	size := uint64(binary.LittleEndian.Uint32(d))
	if size < 16 || size > 1<<20 {
		return 0
	}
	return int(size)
}
func (t *il2cppNativeTypes) token(index int) string {
	if token, ok := t.tokens[index]; ok {
		return token
	}
	v, ok := t.runtime(index)
	if !ok {
		return "unknown:unmapped"
	}
	token := t.typeToken(v, 0)
	t.tokens[index] = token
	return token
}
func (t *il2cppNativeTypes) typeToken(v il2cppRuntimeType, depth int) string {
	if depth > 16 {
		return "unknown:recursive"
	}
	// v39 has the post-2021 bit layout: byref is bit 29.
	if v.bits&(1<<29) != 0 {
		return "ptr:byref"
	}
	kind := byte(v.bits >> 16)
	primitive := map[byte]string{1: "void", 2: "bool", 3: "uint16", 4: "int8", 5: "uint8", 6: "int16", 7: "uint16", 8: "int32", 9: "uint32", 10: "int64", 11: "uint64", 12: "float32", 13: "float64", 0x18: "int64", 0x19: "uint64"}
	if token := primitive[kind]; token != "" {
		return token
	}
	switch kind {
	case 0x0e:
		return "ref:System.String"
	case 0x1c:
		return "ref:System.Object"
	case 0x0f, 0x10:
		return "ptr:native"
	case 0x13, 0x1e:
		return "unknown:generic-parameter"
	case 0x14, 0x1d:
		return "ref:System.Array"
	case 0x11, 0x12, 0x15, 0x16:
		i := t.definition(v, 0)
		if i < 0 {
			return "unknown:class"
		}
		r := t.metadata.types[i]
		name := t.name(i, 0)
		if name == "" {
			return "unknown:class-name"
		}
		if r.bits&2 != 0 {
			if r.fieldCount == 0 {
				return "unknown:enum"
			}
			for _, f := range t.metadata.fields[r.fieldStart : r.fieldStart+r.fieldCount] {
				if f.name == "value__" {
					inner, ok := t.runtime(f.nativeType)
					if ok {
						return t.typeToken(inner, depth+1)
					}
				}
			}
			return "unknown:enum"
		}
		if r.bits&1 == 0 {
			return "ref:" + url.PathEscape(name)
		}
		if kind == 0x15 || r.generic >= 0 {
			return "unknown:generic-value"
		}
		size := t.instanceSize(i) - 16
		if size <= 0 {
			return "unknown:value-size"
		}
		return "val:" + strconv.Itoa(size) + ":" + url.PathEscape(name)
	}
	return "unknown:type-" + strconv.Itoa(int(kind))
}

func (t *il2cppNativeTypes) methodRecords(addresses [][]uint64) []il2cppMethodRecord {
	rows := make([]il2cppMethodRecord, len(t.metadata.methods))
	for i, m := range t.metadata.methods {
		r := il2cppMethodRecord{ID: strconv.Itoa(i), Owner: strconv.Itoa(m.owner), Static: m.flags&0x10 != 0, Ret: t.token(m.ret)}
		for _, va := range addresses[i] {
			r.Addresses = append(r.Addresses, fmt.Sprintf("0x%X", va))
		}
		for p := 0; p < m.parameterCount; p++ {
			r.Params = append(r.Params, t.token(t.metadata.params[m.parameterStart+p]))
		}
		rows[i] = r
	}
	return rows
}

func (t *il2cppNativeTypes) fieldOffset(owner, field int) (int, bool) {
	p, ok := t.image.pointer(t.registration.fieldOffsets + uint64(owner)*8)
	if !ok || p == 0 {
		return 0, false
	}
	if field < 0 {
		return 0, false
	}
	d := t.image.read(p, uint64(field)*4+4)
	if d == nil {
		return 0, false
	}
	n := int(int32(binary.LittleEndian.Uint32(d[len(d)-4:])))
	return n, n >= 16
}

func (t *il2cppNativeTypes) classFields(owner int) []il2cppClassField {
	var fields []il2cppClassField
	seen := map[int]bool{}
	for owner >= 0 && owner < len(t.metadata.types) && len(seen) < 128 && !seen[owner] {
		seen[owner] = true
		r := t.metadata.types[owner]
		if r.generic < 0 && !strings.Contains(t.name(owner, 0), "`") {
			for i := 0; i < r.fieldCount; i++ {
				f := t.metadata.fields[r.fieldStart+i]
				v, ok := t.runtime(f.nativeType)
				if !ok || v.bits&0x50 != 0 {
					continue
				}
				off, ok := t.fieldOffset(owner, i)
				if ok {
					fields = append(fields, il2cppClassField{Name: f.name, Offset: int32(off), Type: t.token(f.nativeType)})
					if len(fields) > 4096 {
						return nil
					}
				}
			}
		}
		p, ok := t.runtime(r.parent)
		if !ok {
			break
		}
		owner = t.definition(p, 0)
	}
	return fields
}
