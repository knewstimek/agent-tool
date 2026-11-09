package analyze

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

type il2cppNativeModule struct{ address, count, pointers uint64 }

func (im *il2cppNativeImage) codeAddress(va uint64) bool {
	for _, s := range im.sections {
		if s.exec && va >= s.va && va-s.va < uint64(len(s.data)) {
			return true
		}
	}
	return false
}

// Match module names once, then inspect aligned references to their strings.
// This avoids one whole-binary scan per assembly or method.
func (im *il2cppNativeImage) modules(m *il2cppNativeMetadata) (map[int]il2cppNativeModule, error) {
	names := map[string]int{}
	for i, a := range m.images {
		if a.name == "" || len(a.name) > 255 {
			return nil, fmt.Errorf("invalid IL2CPP image name")
		}
		if _, duplicate := names[a.name]; duplicate {
			return nil, fmt.Errorf("duplicate IL2CPP image name")
		}
		names[a.name] = i
	}
	namePointers := map[uint64]int{}
	var otherNames []string
	for name := range names {
		if !strings.HasSuffix(name, ".dll") {
			otherNames = append(otherNames, name)
		}
	}
	if len(otherNames) > 16 {
		return nil, fmt.Errorf("too many non-DLL IL2CPP module names")
	}
	for _, s := range im.sections {
		if s.exec {
			continue
		}
		for _, name := range otherNames {
			from := 0
			needle := []byte(name + "\x00")
			for from < len(s.data) {
				at := bytes.Index(s.data[from:], needle)
				if at < 0 {
					break
				}
				namePointers[s.va+uint64(from+at)] = names[name]
				from += at + len(needle)
			}
		}
		from := 0
		for from < len(s.data) {
			n := bytes.Index(s.data[from:], []byte(".dll\x00"))
			if n < 0 {
				break
			}
			end := from + n + 4
			start := end - 4
			for start > 0 && end-start < 256 && s.data[start-1] != 0 {
				start--
			}
			// Native linkers can pool a short module name as a suffix of a
			// longer string. Its pointer need not follow a NUL byte.
			for at := start; at < end; at++ {
				if i, ok := names[string(s.data[at:end])]; ok {
					namePointers[s.va+uint64(at)] = i
				}
			}
			from = end + 1
		}
	}
	maxTokens := make([]uint64, len(m.images))
	for i, a := range m.images {
		if a.count == 0 {
			continue
		}
		for _, td := range m.types[a.start : a.start+a.count] {
			if td.methodCount == 0 {
				continue
			}
			for _, method := range m.methods[td.methodStart : td.methodStart+td.methodCount] {
				if method.token>>24 != 6 {
					return nil, fmt.Errorf("invalid IL2CPP method token")
				}
				if token := uint64(method.token & 0xffffff); token > maxTokens[i] {
					maxTokens[i] = token
				}
			}
		}
	}
	modules := map[int]il2cppNativeModule{}
	diagnostics := map[int][]uint64{}
	for _, s := range im.sections {
		if s.exec {
			continue
		}
		for off := 0; off+24 <= len(s.data); off += 8 {
			i, ok := namePointers[binary.LittleEndian.Uint64(s.data[off:])]
			if !ok {
				continue
			}
			n, ptr := binary.LittleEndian.Uint64(s.data[off+8:]), binary.LittleEndian.Uint64(s.data[off+16:])
			if len(diagnostics[i]) < 8 {
				diagnostics[i] = append(diagnostics[i], n)
			}
			if n > maxIL2CPPMethods || n > 0 && ptr != 0 && im.read(ptr, n*8) == nil {
				continue
			}
			if _, exists := modules[i]; exists {
				return nil, fmt.Errorf("ambiguous IL2CPP code generation module")
			}
			modules[i] = il2cppNativeModule{s.va + uint64(off), n, ptr}
		}
	}
	for i := range m.images {
		if _, ok := modules[i]; !ok && maxTokens[i] != 0 {
			return nil, fmt.Errorf("IL2CPP code generation module missing for image %d %q (%d method tokens; candidate sizes %v)", i, m.images[i].name, maxTokens[i], diagnostics[i])
		}
	}
	return modules, nil
}

func (im *il2cppNativeImage) methodAddresses(m *il2cppNativeMetadata, r il2cppNativeRegistration) ([][]uint64, error) {
	modules, err := im.modules(m)
	if err != nil {
		return nil, err
	}
	addresses := make([][]uint64, len(m.methods))
	add := func(index int, va uint64) error {
		if va == 0 {
			return nil
		}
		if index < 0 || index >= len(addresses) || !im.codeAddress(va) {
			return fmt.Errorf("invalid IL2CPP method pointer")
		}
		for _, old := range addresses[index] {
			if old == va {
				return nil
			}
		}
		addresses[index] = append(addresses[index], va)
		return nil
	}
	for i, a := range m.images {
		if a.count == 0 {
			continue
		}
		module := modules[i]
		if module.pointers == 0 {
			continue // generic-only modules have a NULL direct pointer array
		}
		for _, td := range m.types[a.start : a.start+a.count] {
			if td.methodCount == 0 {
				continue
			}
			for index := td.methodStart; index < td.methodStart+td.methodCount; index++ {
				token := uint64(m.methods[index].token & 0xffffff)
				if token == 0 {
					return nil, fmt.Errorf("IL2CPP method token exceeds module")
				}
				if token > module.count {
					continue // metadata-only methods have no native pointer slot
				}
				va, ok := im.pointer(module.pointers + (token-1)*8)
				if !ok {
					return nil, fmt.Errorf("unmapped IL2CPP method pointer")
				}
				if err := add(index, va); err != nil {
					return nil, err
				}
			}
		}
	}
	// v39 CodeRegistration ends with its counted codegen-module array.
	moduleSet := map[uint64]bool{}
	for _, mod := range modules {
		moduleSet[mod.address] = true
	}
	var roots []uint64
	for _, s := range im.sections {
		if s.exec {
			continue
		}
		for off := 0x78; off+16 <= len(s.data); off += 8 {
			if binary.LittleEndian.Uint64(s.data[off:]) != uint64(len(modules)) {
				continue
			}
			ptr := binary.LittleEndian.Uint64(s.data[off+8:])
			data := im.read(ptr, uint64(len(modules))*8)
			if data == nil {
				continue
			}
			seen := map[uint64]bool{}
			for p := 0; p < len(data); p += 8 {
				v := binary.LittleEndian.Uint64(data[p:])
				if !moduleSet[v] {
					break
				}
				seen[v] = true
			}
			if len(seen) == len(modules) {
				roots = append(roots, s.va+uint64(off)-0x78)
			}
		}
	}
	if len(roots) != 1 {
		return nil, fmt.Errorf("IL2CPP code registration is ambiguous or missing (%d candidates)", len(roots))
	}
	genCount, _ := im.pointer(roots[0] + 0x10)
	genPointers, _ := im.pointer(roots[0] + 0x18)
	tableCount, _ := im.pointer(r.address + 0x20)
	tablePointer, _ := im.pointer(r.address + 0x28)
	specCount, _ := im.pointer(r.address + 0x40)
	specPointer, _ := im.pointer(r.address + 0x48)
	if genCount > maxIL2CPPMethods || tableCount > maxIL2CPPMethods || specCount > maxIL2CPPMethods {
		return nil, fmt.Errorf("IL2CPP generic table limit exceeded")
	}
	gp, table, specs := im.read(genPointers, genCount*8), im.read(tablePointer, tableCount*16), im.read(specPointer, specCount*12)
	if genCount > 0 && gp == nil || tableCount > 0 && table == nil || specCount > 0 && specs == nil {
		return nil, fmt.Errorf("unmapped IL2CPP generic tables")
	}
	for i := uint64(0); i < tableCount; i++ {
		entry := table[i*16:]
		spec, method := uint64(binary.LittleEndian.Uint32(entry)), uint64(binary.LittleEndian.Uint32(entry[4:]))
		if spec >= specCount || method >= genCount {
			return nil, fmt.Errorf("invalid IL2CPP generic mapping")
		}
		index := int(binary.LittleEndian.Uint32(specs[spec*12:]))
		va := binary.LittleEndian.Uint64(gp[method*8:])
		if err := add(index, va); err != nil {
			return nil, err
		}
	}
	return addresses, nil
}

func il2cppNativeQualifiedName(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return strings.TrimSuffix(namespace, ".") + "." + name
}
