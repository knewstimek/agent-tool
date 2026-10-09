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

// switchTargets64 resolves the dispatch ending in the jmp at pos of data
// (whose first byte is at baseVA) and returns the case target VAs.
func switchTargets64(data []byte, baseVA uint64, pos int, jmp x86asm.Inst, read vaReader, inCode func(uint64) bool) []uint64 {
	target, ok := jmp.Args[0].(x86asm.Reg)
	if !ok || jmp.Op != x86asm.JMP {
		return nil
	}
	// add rTarget, rB right before the jmp.
	add, addPos, ok := instEndingAt(data, pos, 3, 4, func(in x86asm.Inst) bool {
		return in.Op == x86asm.ADD && sameReg(regArg(in, 0), target) && regArg(in, 1) != 0
	})
	if !ok {
		return nil
	}
	b := regArg(add, 1)
	// The table load right before the add.
	load, loadPos, ok := instEndingAt(data, addPos, 4, 9, func(in x86asm.Inst) bool {
		m, isMem := in.Args[1].(x86asm.Mem)
		return (in.Op == x86asm.MOV || in.Op == x86asm.MOVSXD) && sameReg(regArg(in, 0), target) &&
			isMem && m.Base == b && m.Index != 0 && m.Scale == 4
	})
	if !ok {
		return nil
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
		return nil
	}
	count := switchBound(data, max(0, limit-48), loadPos, 64)
	table := base + uint64(memDisp(m))
	signed := load.Op == x86asm.MOVSXD
	var out []uint64
	for i := 0; i < maxSwitchCases && (count == 0 || i < count); i++ {
		raw := read(table+uint64(4*i), 4)
		if raw == nil {
			break
		}
		e := uint64(binary.LittleEndian.Uint32(raw))
		if signed {
			e = uint64(int64(int32(uint32(e))))
		}
		t := base + e
		if !inCode(t) {
			if count == 0 {
				break
			}
			return nil // a bounded table must be all code: not a switch
		}
		out = append(out, t)
	}
	return out
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
func switchTargets32(data []byte, pos int, jmp x86asm.Inst, read vaReader, inCode func(uint64) bool) []uint64 {
	m, ok := jmp.Args[0].(x86asm.Mem)
	if !ok || jmp.Op != x86asm.JMP || m.Base != 0 || m.Index == 0 || m.Scale != 4 {
		return nil
	}
	count := switchBound(data, max(0, pos-48), pos, 32)
	table := uint64(uint32(m.Disp))
	var out []uint64
	for i := 0; i < maxSwitchCases && (count == 0 || i < count); i++ {
		raw := read(table+uint64(4*i), 4)
		if raw == nil {
			break
		}
		t := uint64(binary.LittleEndian.Uint32(raw))
		if !inCode(t) {
			if count == 0 {
				break
			}
			return nil
		}
		out = append(out, t)
	}
	return out
}

// switchCases resolves the switch jump at pos of data (first byte at
// baseVA) to case target VAs for either mode.
func switchCases(data []byte, baseVA uint64, pos int, jmp x86asm.Inst, mode int, read vaReader, inCode func(uint64) bool) []uint64 {
	if mode == 64 {
		return switchTargets64(data, baseVA, pos, jmp, read, inCode)
	}
	return switchTargets32(data, pos, jmp, read, inCode)
}
