package analyze

import (
	"debug/pe"
	"encoding/binary"
)

// pdataIndex is the x64 .pdata function table with chained entries resolved.
// A chained entry (UNW_FLAG_CHAININFO) covers a split-off part of a function
// -- a cold block the compiler moved away -- not a function of its own: it is
// neither a call target to name nor a tail-jump destination.
type pdataIndex struct {
	table   []funcRange       // every .pdata entry, sorted
	primary map[uint32]uint32 // chained entry begin -> primary function begin
}

func loadPdata(f *pe.File, imageBase uint64) *pdataIndex {
	table := buildFuncTable(f, imageBase)
	if len(table) == 0 {
		return nil
	}
	// Section bytes are read once: Data() re-reads the whole section per call.
	cache := map[*pe.Section][]byte{}
	read := func(rva uint32, n int) []byte {
		for _, s := range f.Sections {
			if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
				data, ok := cache[s]
				if !ok {
					data, _ = s.Data()
					cache[s] = data
				}
				off := int(rva - s.VirtualAddress)
				if off+n > len(data) {
					return nil
				}
				return data[off : off+n]
			}
		}
		return nil
	}
	unwind := map[uint32]uint32{}
	if oh, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok && len(oh.DataDirectory) > 3 {
		dir := oh.DataDirectory[3]
		if raw := read(dir.VirtualAddress, int(dir.Size)); raw != nil {
			for i := 0; i+12 <= len(raw); i += 12 {
				unwind[binary.LittleEndian.Uint32(raw[i:])] = binary.LittleEndian.Uint32(raw[i+8:])
			}
		}
	}
	// chainParent is the RUNTIME_FUNCTION a chained entry's unwind info points
	// back to; it follows the unwind codes, padded to an even count.
	chainParent := func(begin uint32) (uint32, bool) {
		u, ok := unwind[begin]
		if !ok {
			return 0, false
		}
		info := read(u, 4)
		if info == nil || info[0]>>3&0x4 == 0 { // UNW_FLAG_CHAININFO
			return 0, false
		}
		chain := read(u+4+uint32(2*((int(info[2])+1)&^1)), 12)
		if chain == nil {
			return 0, false
		}
		return binary.LittleEndian.Uint32(chain), true
	}
	p := &pdataIndex{table: table, primary: map[uint32]uint32{}}
	for _, fr := range table {
		begin, chained := fr.begin, false
		for hop := 0; hop < 32; hop++ {
			parent, ok := chainParent(begin)
			if !ok || parent == begin {
				break
			}
			begin, chained = parent, true
		}
		if chained {
			p.primary[fr.begin] = begin
		}
	}
	return p
}

// containing returns the primary function start for the .pdata entry that
// covers va.
func (p *pdataIndex) containing(imageBase, va uint64) (uint64, bool) {
	if va < imageBase || va-imageBase > 0xffffffff {
		return 0, false
	}
	fr := findFunc(p.table, uint32(va-imageBase))
	if fr == nil {
		return 0, false
	}
	begin := fr.begin
	if prim, ok := p.primary[begin]; ok {
		begin = prim
	}
	return imageBase + uint64(begin), true
}
