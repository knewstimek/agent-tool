package analyze

import (
	"encoding/binary"

	"golang.org/x/arch/x86/x86asm"
)

// x64 switch dispatch through a register, as MSVC and GCC/Clang emit it:
//
//	MSVC:  lea  rB, [__ImageBase]          GCC/Clang: lea    rB, [table]
//	       mov  ecx, [rB+rI*4+tableRVA]               movsxd rax, [rB+rI*4]
//	       add  rcx, rB                               add    rax, rB
//	       jmp  rcx                                   jmp    rax
//
// Both are base + table[index] with a 4-byte entry: the MSVC base is the
// image base and the entries are RVAs, the GCC base is the table and the
// entries are offsets from it. The case count comes from the bounds check
// (cmp rI, N; ja default) when it is in reach, else entries are read while
// they land in executable code. Plain instruction matching, no decompiler:
// a dispatch that does not have this shape is left unresolved.

const maxSwitchCases = 1024

// vaReader returns n bytes at va from the image's mapped sections, nil if
// the range is not file-backed.
type vaReader func(va uint64, n int) []byte

// switchInfo is a resolved switch dispatch: the 4-byte entry table and the
// case target of each entry, plus, when the compiler maps sparse case values
// through a byte table first (movzx idx, byte [idxTable+idx]), that table.
type switchInfo struct {
	table    uint64
	cases    []uint64
	index    uint64 // byte index table VA, 0 when none
	indexLen int
}

// byteIndexTable recognizes the MSVC two-level dispatch: the instruction
// ending at end is movzx idx, byte [mem] where idx is the entry table's
// index register. It reads the n byte entries the bounds check allows and
// returns the table's VA and the entry table's size (largest byte + 1).
func byteIndexTable(data []byte, end, mode int, idx x86asm.Reg, n int, addr func(x86asm.Mem) (uint64, bool), read vaReader) (uint64, int, bool) {
	if n <= 0 {
		return 0, 0, false
	}
	for k := 4; k <= 9 && end-k >= 0; k++ {
		in, err := x86asm.Decode(data[end-k:], mode)
		if err != nil || in.Len != k || in.Op != x86asm.MOVZX || !sameReg(regArg(in, 0), idx) {
			continue
		}
		m, ok := in.Args[1].(x86asm.Mem)
		if !ok || in.MemBytes != 1 {
			continue
		}
		va, ok := addr(m)
		if !ok {
			return 0, 0, false
		}
		raw := read(va, n)
		if raw == nil {
			return 0, 0, false
		}
		hi := 0
		for _, b := range raw {
			hi = max(hi, int(b))
		}
		return va, hi + 1, true
	}
	return 0, 0, false
}

// readCases reads count 4-byte entries at table (count 0: while they land in
// code) and maps each through entry. A bounded table must be all code.
func readCases(table uint64, count int, read vaReader, inCode func(uint64) bool, entry func(uint32) uint64) []uint64 {
	var out []uint64
	for i := 0; i < maxSwitchCases && (count == 0 || i < count); i++ {
		raw := read(table+uint64(4*i), 4)
		if raw == nil {
			break
		}
		t := entry(binary.LittleEndian.Uint32(raw))
		if !inCode(t) {
			if count == 0 {
				break
			}
			return nil // not a switch
		}
		out = append(out, t)
	}
	return out
}

// switchTargets64 resolves the dispatch ending in the jmp at pos of data
// (whose first byte is at baseVA).
func switchTargets64(data []byte, baseVA uint64, pos int, jmp x86asm.Inst, read vaReader, inCode func(uint64) bool) switchInfo {
	target, ok := jmp.Args[0].(x86asm.Reg)
	if !ok || jmp.Op != x86asm.JMP {
		return switchInfo{}
	}
	// add rTarget, rB right before the jmp.
	add, addPos, ok := instEndingAt(data, pos, 3, 4, func(in x86asm.Inst) bool {
		return in.Op == x86asm.ADD && sameReg(regArg(in, 0), target) && regArg(in, 1) != 0
	})
	if !ok {
		return switchInfo{}
	}
	b := regArg(add, 1)
	// The table load right before the add.
	load, loadPos, ok := instEndingAt(data, addPos, 4, 9, func(in x86asm.Inst) bool {
		m, isMem := in.Args[1].(x86asm.Mem)
		return (in.Op == x86asm.MOV || in.Op == x86asm.MOVSXD) && sameReg(regArg(in, 0), target) &&
			isMem && m.Base == b && m.Index != 0 && m.Scale == 4
	})
	if !ok {
		return switchInfo{}
	}
	m := load.Args[1].(x86asm.Mem)
	// The base: the closest lea rB, [rip+d] before the load.
	var base uint64
	found := false
	limit := 0
	for p := loadPos - 1; p >= max(0, loadPos-64); p-- {
		in, err := x86asm.Decode(data[p:], 64)
		if err != nil || p+in.Len > loadPos || in.Op != x86asm.LEA || !sameReg(regArg(in, 0), b) {
			continue
		}
		if lm, ok := in.Args[1].(x86asm.Mem); ok && lm.Base == x86asm.RIP {
			base = baseVA + uint64(p+in.Len) + uint64(memDisp(lm))
			found = true
			limit = p
			break
		}
	}
	if !found {
		return switchInfo{}
	}
	info := switchInfo{table: base + uint64(memDisp(m))}
	count := switchBound(data, max(0, limit-48), loadPos, 64)
	// The bound counts case values; through a byte index table it bounds
	// that table, and the entry table is as long as its largest byte.
	if va, n, ok := byteIndexTable(data, loadPos, 64, m.Index, count, func(bm x86asm.Mem) (uint64, bool) {
		return base + uint64(memDisp(bm)), bm.Base == b && bm.Scale == 1
	}, read); ok {
		info.index, info.indexLen, count = va, count, n
	}
	signed := load.Op == x86asm.MOVSXD
	info.cases = readCases(info.table, count, read, inCode, func(e uint32) uint64 {
		if signed {
			return base + uint64(int64(int32(e)))
		}
		return base + uint64(e)
	})
	return info
}

// switchBound finds the cmp index, N that guards the dispatch in
// data[from:to] and returns N+1 cases, or 0 when it is not found.
func switchBound(data []byte, from, to, mode int) int {
	n := 0
	for p := from; p < to; {
		in, err := x86asm.Decode(data[p:], mode)
		if err != nil || in.Len == 0 {
			p++
			continue
		}
		// The index is often compared in another register first
		// (cmp esi, 5; ja; movsxd rax, esi): the last cmp reg, N counts.
		if in.Op == x86asm.CMP && regArg(in, 0) != 0 {
			if imm, ok := in.Args[1].(x86asm.Imm); ok && imm >= 0 && imm < maxSwitchCases {
				n = int(imm) + 1
			}
		}
		p += in.Len
	}
	return n
}

// instEndingAt finds an instruction of minLen..maxLen bytes ending exactly at
// end that has the expected shape. Decoding backwards is ambiguous -- a
// suffix of the real instruction often decodes too -- so the shape decides.
func instEndingAt(data []byte, end, minLen, maxLen int, want func(x86asm.Inst) bool) (x86asm.Inst, int, bool) {
	for k := minLen; k <= maxLen && end-k >= 0; k++ {
		in, err := x86asm.Decode(data[end-k:], 64)
		if err == nil && in.Len == k && want(in) {
			return in, end - k, true
		}
	}
	return x86asm.Inst{}, 0, false
}

func regArg(in x86asm.Inst, i int) x86asm.Reg {
	if r, ok := in.Args[i].(x86asm.Reg); ok {
		return r
	}
	return 0
}

// readerFor maps VAs into the given sections.
func readerFor(imageBase uint64, sections ...[]cgSection) vaReader {
	return func(va uint64, n int) []byte {
		if va < imageBase {
			return nil
		}
		rva := va - imageBase
		for _, secs := range sections {
			for _, s := range secs {
				if rva >= uint64(s.rva) && rva+uint64(n) <= uint64(s.rva)+uint64(len(s.data)) {
					return s.data[rva-uint64(s.rva) : rva-uint64(s.rva)+uint64(n)]
				}
			}
		}
		return nil
	}
}

// switchTargets32 resolves an x86 jmp [index*4+table] (MSVC): a table of
// absolute case addresses, bounded by the preceding cmp when found.
func switchTargets32(data []byte, pos int, jmp x86asm.Inst, read vaReader, inCode func(uint64) bool) switchInfo {
	m, ok := jmp.Args[0].(x86asm.Mem)
	if !ok || jmp.Op != x86asm.JMP || m.Base != 0 || m.Index == 0 || m.Scale != 4 {
		return switchInfo{}
	}
	info := switchInfo{table: uint64(uint32(m.Disp))}
	count := switchBound(data, max(0, pos-48), pos, 32)
	// movzx idx, byte [idx+indexTable] (absolute disp32) before the jmp.
	if va, n, ok := byteIndexTable(data, pos, 32, m.Index, count, func(bm x86asm.Mem) (uint64, bool) {
		return uint64(uint32(bm.Disp)), bm.Index == 0 && sameReg(bm.Base, m.Index) || bm.Base == 0 && sameReg(bm.Index, m.Index) && bm.Scale == 1
	}, read); ok {
		info.index, info.indexLen, count = va, count, n
	}
	info.cases = readCases(info.table, count, read, inCode, func(e uint32) uint64 { return uint64(e) })
	return info
}

// switchCases resolves the switch jump at pos of data (first byte at
// baseVA) to case target VAs for either mode.
func switchCases(data []byte, baseVA uint64, pos int, jmp x86asm.Inst, mode int, read vaReader, inCode func(uint64) bool) []uint64 {
	return switchTable(data, baseVA, pos, jmp, mode, read, inCode).cases
}

// switchTable is switchCases with the tables' locations.
func switchTable(data []byte, baseVA uint64, pos int, jmp x86asm.Inst, mode int, read vaReader, inCode func(uint64) bool) switchInfo {
	if mode == 64 {
		return switchTargets64(data, baseVA, pos, jmp, read, inCode)
	}
	return switchTargets32(data, pos, jmp, read, inCode)
}
