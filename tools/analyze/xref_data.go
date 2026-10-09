package analyze

import (
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
)

// xrefDataSection is a non-executable section scanned for stored pointers
// (vtables, function-pointer tables, callback registrations, string tables).
type xrefDataSection struct {
	name string
	rva  uint32
	data []byte
}

// peRelocSlots returns the sorted RVAs the base relocation table patches
// (HIGHLOW and DIR64): exactly the slots that hold absolute pointers. With it
// a data scan reports only real pointers, never a constant that happens to
// equal the target.
func peRelocSlots(f *pe.File) []uint32 {
	var dir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 5 {
			dir = oh.DataDirectory[5]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 5 {
			dir = oh.DataDirectory[5]
		}
	}
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil
	}
	var table []byte
	for _, s := range f.Sections {
		if dir.VirtualAddress >= s.VirtualAddress && dir.VirtualAddress < s.VirtualAddress+max(s.VirtualSize, s.Size) {
			data, err := s.Data()
			if err != nil {
				return nil
			}
			off := dir.VirtualAddress - s.VirtualAddress
			if uint64(off) >= uint64(len(data)) {
				return nil
			}
			table = data[off:min(uint64(len(data)), uint64(off)+uint64(dir.Size))]
			break
		}
	}
	var slots []uint32
	for len(table) >= 8 {
		page := binary.LittleEndian.Uint32(table)
		size := binary.LittleEndian.Uint32(table[4:])
		if size < 8 || uint64(size) > uint64(len(table)) {
			break
		}
		for i := 8; i+2 <= int(size); i += 2 {
			e := binary.LittleEndian.Uint16(table[i:])
			if t := e >> 12; t == 3 || t == 10 { // IMAGE_REL_BASED_HIGHLOW, _DIR64
				slots = append(slots, page+uint32(e&0xFFF))
			}
		}
		table = table[size:]
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i] < slots[j] })
	return slots
}

// elfRelativeTargets reads R_*_RELATIVE relocations: in a PIE the stored
// pointer is 0 in the file and the target lives in the addend, so a raw
// data scan would miss every pointer. Keys are slot RVAs, values target RVAs.
func elfRelativeTargets(f *elf.File, imageBase uint64) map[uint32]uint32 {
	var relative uint32
	switch f.Machine {
	case elf.EM_X86_64:
		relative = uint32(elf.R_X86_64_RELATIVE)
	case elf.EM_AARCH64:
		relative = uint32(elf.R_AARCH64_RELATIVE)
	default:
		return nil // 32-bit REL keeps the addend in place: the raw scan sees it
	}
	out := make(map[uint32]uint32)
	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		for i := 0; i+24 <= len(data); i += 24 {
			off := binary.LittleEndian.Uint64(data[i:])
			info := binary.LittleEndian.Uint64(data[i+8:])
			addend := binary.LittleEndian.Uint64(data[i+16:])
			if uint32(info) != relative || off < imageBase || addend < imageBase {
				continue
			}
			if off-imageBase > 0xFFFFFFFF || addend-imageBase > 0xFFFFFFFF {
				continue
			}
			out[uint32(off-imageBase)] = uint32(addend - imageBase)
		}
	}
	return out
}

// collectXrefData finds stored pointers into targetRange in data sections.
// PE images with a relocation table report only relocated slots; without one
// (fixed-base executables) every aligned pointer-sized value is a candidate.
func collectXrefData(bin *xrefBinary, target xrefTargetRange, maxRes, found int, refs []xrefResult) ([]xrefResult, int) {
	ptrSize := 4
	if bin.arch == "x64" || bin.arch == "arm64" {
		ptrSize = 8
	}
	inRelocs := func(rva uint32) bool {
		i := sort.Search(len(bin.relocSlots), func(i int) bool { return bin.relocSlots[i] >= rva })
		return i < len(bin.relocSlots) && bin.relocSlots[i] == rva
	}
	seen := make(map[uint32]bool)
	for _, sec := range bin.dataSections {
		for i := 0; i+ptrSize <= len(sec.data) && found < maxRes; i += ptrSize {
			var v uint64
			if ptrSize == 8 {
				v = binary.LittleEndian.Uint64(sec.data[i:])
			} else {
				v = uint64(binary.LittleEndian.Uint32(sec.data[i:]))
			}
			if !target.containsVA(v) {
				continue
			}
			slot := sec.rva + uint32(i)
			if bin.hasRelocs && !inRelocs(slot) {
				continue
			}
			seen[slot] = true
			refs = append(refs, xrefResult{refType: "PTR", line: fmt.Sprintf("  0x%x: pointer to 0x%x in %s\n", bin.imageBase+uint64(slot), v, sec.name)})
			found++
		}
	}
	// PIE relocations: the file holds 0 where the loader writes the pointer.
	slots := make([]uint32, 0, len(bin.relative))
	for slot, t := range bin.relative {
		if !seen[slot] && target.containsVA(bin.imageBase+uint64(t)) {
			slots = append(slots, slot)
		}
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i] < slots[j] })
	for _, slot := range slots {
		if found >= maxRes {
			break
		}
		name := ""
		for _, sec := range bin.dataSections {
			if slot >= sec.rva && uint64(slot) < uint64(sec.rva)+uint64(len(sec.data)) {
				name = " in " + sec.name
				break
			}
		}
		refs = append(refs, xrefResult{refType: "PTR", line: fmt.Sprintf("  0x%x: pointer to 0x%x%s (RELATIVE relocation)\n",
			bin.imageBase+uint64(slot), bin.imageBase+uint64(bin.relative[slot]), name)})
		found++
	}
	return refs, found
}
