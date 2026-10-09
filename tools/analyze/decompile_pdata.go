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
	unwind  map[uint32]uint32 // function begin -> UNWIND_INFO RVA
	read    func(rva uint32, n int) []byte
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
	p := &pdataIndex{table: table, primary: map[uint32]uint32{}, unwind: unwind, read: read}
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

// x64 unwind operations (UNWIND_CODE.UnwindOp).
const (
	uwopPushNonvol    = 0
	uwopAllocLarge    = 1
	uwopAllocSmall    = 2
	uwopSetFPReg      = 3
	uwopSaveNonvol    = 4
	uwopSaveNonvolFar = 5
	uwopEpilog        = 6 // version 2 only
	uwopSaveXMM128    = 8
	uwopSaveXMM128Far = 9
	uwopPushMachframe = 10
)

// prologueFrame is a function's stack frame as its unwind codes record the
// prologue, relative to the stack pointer at entry (the return address at 0).
type prologueFrame struct {
	rsp   int64 // RSP once the prologue has run (all pushes and allocations)
	fp    int64 // where the frame register points, when fpReg != 0
	fpReg int   // frame register number (5 for RBP), 0 when none
}

// frame decodes the function's unwind codes. They record the prologue in
// reverse; the frame register is RSP plus 16*FrameOffset at the point of
// UWOP_SET_FPREG. Pushes are not all counted in the PDB's S_FRAMEPROC
// (SaveRegsSize can be 0 with three pushes), so only this gives the RSP the
// PDB's RSP-relative offsets are measured from.
func (p *pdataIndex) frame(imageBase, entry uint64) (prologueFrame, bool) {
	var fr prologueFrame
	if p == nil || entry < imageBase || entry-imageBase > 0xffffffff {
		return fr, false
	}
	u, found := p.unwind[uint32(entry-imageBase)]
	if !found {
		return fr, false
	}
	hdr := p.read(u, 4)
	if hdr == nil {
		return fr, false
	}
	version, count := hdr[0]&7, int(hdr[2])
	if hdr[0]>>3&0x4 != 0 { // UNW_FLAG_CHAININFO: a split-off part, not an entry
		return fr, false
	}
	codes := p.read(u+4, 2*count)
	if codes == nil {
		return fr, false
	}
	type op struct {
		code   byte
		adjust int64 // bytes the operation moves RSP down
	}
	var ops []op
	for i := 0; i < count; {
		code, info := codes[2*i+1]&0xf, int64(codes[2*i+1]>>4)
		slots, adjust := 1, int64(0)
		switch code {
		case uwopPushNonvol:
			adjust = 8
		case uwopAllocLarge:
			if info == 0 {
				slots = 2
				if 2*i+4 > len(codes) {
					return fr, false
				}
				adjust = int64(binary.LittleEndian.Uint16(codes[2*i+2:])) * 8
			} else {
				slots = 3
				if 2*i+6 > len(codes) {
					return fr, false
				}
				adjust = int64(binary.LittleEndian.Uint32(codes[2*i+2:]))
			}
		case uwopAllocSmall:
			adjust = info*8 + 8
		case uwopSetFPReg:
		case uwopSaveNonvol, uwopSaveXMM128:
			slots = 2
		case uwopSaveNonvolFar, uwopSaveXMM128Far:
			slots = 3
		case uwopEpilog:
			if version < 2 {
				return fr, false
			}
			slots = 2
		case uwopPushMachframe:
			adjust = 40
			if info == 1 {
				adjust = 48
			}
		default:
			return fr, false
		}
		ops = append(ops, op{code: code, adjust: adjust})
		i += slots
	}
	for i := len(ops) - 1; i >= 0; i-- { // prologue order
		if ops[i].code == uwopSetFPReg && hdr[3]&0xf != 0 {
			fr.fp, fr.fpReg = fr.rsp+16*int64(hdr[3]>>4), int(hdr[3]&0xf)
		}
		fr.rsp -= ops[i].adjust
	}
	return fr, true
}
