package analyze

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

// Native extraction reads data only. It never loads or executes the input DLL.
type il2cppNativeSection struct {
	va   uint64
	data []byte
	exec bool
}

type il2cppNativeImage struct {
	sections []il2cppNativeSection
	exports  map[string]uint64
	base     uint64
}

func openIL2CPPNativeImage(path string) (*il2cppNativeImage, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > 512<<20 {
		return nil, fmt.Errorf("IL2CPP binary must be a regular file of at most 512 MiB")
	}
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return nil, fmt.Errorf("native IL2CPP extraction currently requires an x64 PE image")
	}
	image := &il2cppNativeImage{base: h.ImageBase, exports: map[string]uint64{}}
	var total uint64
	for _, section := range f.Sections {
		mappedSize := max(section.Size, section.VirtualSize)
		total += uint64(mappedSize)
		if total > 512<<20 || uint64(section.VirtualAddress) > ^uint64(0)-image.base {
			return nil, fmt.Errorf("IL2CPP mapped section limit exceeded")
		}
		va := image.base + uint64(section.VirtualAddress)
		if uint64(mappedSize) > ^uint64(0)-va {
			return nil, fmt.Errorf("IL2CPP section address overflows")
		}
		for _, previous := range image.sections {
			if mappedSize > 0 && len(previous.data) > 0 && va < previous.va+uint64(len(previous.data)) && previous.va < va+uint64(mappedSize) {
				return nil, fmt.Errorf("overlapping IL2CPP mapped sections")
			}
		}
		data, err := section.Data()
		if err != nil {
			return nil, err
		}
		// PE .bss and virtual tails are zero-initialized by the loader. IL2CPP
		// generic-only modules can keep their NULL pointer arrays there.
		if uint64(len(data)) < uint64(mappedSize) {
			mapped := make([]byte, int(mappedSize))
			copy(mapped, data)
			data = mapped
		}
		image.sections = append(image.sections, il2cppNativeSection{va: image.base + uint64(section.VirtualAddress), data: data, exec: section.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0})
	}
	for _, export := range parseExports(f) {
		if !export.forwarder {
			image.exports[export.name] = image.base + uint64(export.rva)
		}
	}
	return image, nil
}

func (im *il2cppNativeImage) read(va, size uint64) []byte {
	for _, s := range im.sections {
		if va >= s.va && va-s.va <= uint64(len(s.data)) && size <= uint64(len(s.data))-(va-s.va) {
			return s.data[va-s.va : va-s.va+size]
		}
	}
	return nil
}

func (im *il2cppNativeImage) pointer(va uint64) (uint64, bool) {
	data := im.read(va, 8)
	if data == nil {
		return 0, false
	}
	return binary.LittleEndian.Uint64(data), true
}

type il2cppNativeRegistration struct {
	address, typesCount, types, fieldOffsets, typeSizes uint64
}

// The v39 registration has counted arrays of field-offset tables and type-size
// records indexed by the metadata type-definition count. Require a unique match
// and mapped array ranges; a count appearing alone in arbitrary data is no proof.
func (im *il2cppNativeImage) registrationV39(typeCount uint64) (il2cppNativeRegistration, error) {
	var found []il2cppNativeRegistration
	if typeCount == 0 || typeCount > maxIL2CPPMethods {
		return il2cppNativeRegistration{}, fmt.Errorf("invalid IL2CPP type-definition count")
	}
	for _, s := range im.sections {
		if s.exec {
			continue
		}
		for off := 0; off+0x70 <= len(s.data); off += 8 {
			u := func(index int) uint64 { return binary.LittleEndian.Uint64(s.data[off+index:]) }
			if u(0x50) != typeCount || u(0x60) != typeCount {
				continue
			}
			n, types, fields, sizes := u(0x30), u(0x38), u(0x58), u(0x68)
			if n == 0 || n > maxIL2CPPMethods || im.read(types, n*8) == nil || im.read(fields, typeCount*8) == nil || im.read(sizes, typeCount*8) == nil {
				continue
			}
			found = append(found, il2cppNativeRegistration{address: s.va + uint64(off), typesCount: n, types: types, fieldOffsets: fields, typeSizes: sizes})
		}
	}
	if len(found) != 1 {
		return il2cppNativeRegistration{}, fmt.Errorf("IL2CPP metadata registration is ambiguous or missing (%d candidates)", len(found))
	}
	return found[0], nil
}
