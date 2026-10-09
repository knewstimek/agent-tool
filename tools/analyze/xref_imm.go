package analyze

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

// collectXrefImm finds x86/x64 instructions that carry a target address as an
// immediate or an absolute (base-less) displacement: mov reg, imm; mov [m],
// imm; push/cmp imm; mov rax, imm64; x86 mov reg, [abs]. The byte patterns in
// collectXref32/64 cover only a few encodings of these. A candidate is any
// position whose 4- or 8-byte value lies in the target range; the instruction
// holding it is found by decoding from the few bytes before it, so only those
// positions pay for a decode. Instructions already reported (by VA) are
// skipped.
func collectXrefImm(data []byte, secRVA uint32, target xrefTargetRange, mode int, reported map[uint64]bool, maxRes, found int, refs []xrefResult) ([]xrefResult, int) {
	imageBase := target.imageBase
	// x64 code holds a full address only as imm64 (mov r64, imm64), or as a
	// sign-extended imm32/disp32 when the image sits below 2 GB (non-PIE ELF).
	low32 := mode == 32 || target.endVA <= 0x7FFFFFFF
	for p := 0; p+4 <= len(data) && found < maxRes; p++ {
		var start int
		var inst x86asm.Inst
		ok := false
		if v := uint64(binary.LittleEndian.Uint32(data[p:])); low32 && target.containsVA(v) {
			start, inst, ok = decodeHolding(data, p, 4, v, mode)
		}
		if v := uint64(0); !ok && mode == 64 && p+8 <= len(data) {
			if v = binary.LittleEndian.Uint64(data[p:]); target.containsVA(v) {
				start, inst, ok = decodeHolding(data, p, 8, v, mode)
			}
		}
		if !ok {
			continue
		}
		va := imageBase + uint64(secRVA) + uint64(start)
		if reported[va] {
			continue
		}
		reported[va] = true
		refType, how := immRefType(inst)
		refs = append(refs, xrefResult{refType: refType, line: fmt.Sprintf("  0x%x: %s  (%s)\n", va, xrefAsm(inst, va), how)})
		found++
		p = start + inst.Len - 1
	}
	return refs, found
}

// decodeHolding finds the instruction whose immediate or absolute
// displacement is the width bytes at p. The nearest start wins; a legacy or
// REX prefix just before it is folded in when the longer decode ends at the
// same byte and still carries the value.
func decodeHolding(data []byte, p, width int, value uint64, mode int) (int, x86asm.Inst, bool) {
	for k := 1; k <= 10 && p-k >= 0; k++ {
		s := p - k
		inst, err := x86asm.Decode(data[s:], mode)
		if err != nil || s+inst.Len != p+width || !carriesValue(inst, value, width) {
			continue
		}
		for s > 0 && isPrefixByte(data[s-1], mode) {
			wider, err := x86asm.Decode(data[s-1:], mode)
			if err != nil || s-1+wider.Len != p+width || !carriesValue(wider, value, width) {
				break
			}
			s, inst = s-1, wider
		}
		return s, inst, true
	}
	return 0, x86asm.Inst{}, false
}

func isPrefixByte(b byte, mode int) bool {
	switch b {
	case 0x66, 0x67, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65:
		return true
	}
	return mode == 64 && b >= 0x40 && b <= 0x4F
}

// carriesValue reports whether inst encodes value as an immediate or as a
// memory operand with no base or index register (an absolute address).
func carriesValue(inst x86asm.Inst, value uint64, width int) bool {
	mask := uint64(1)<<(8*width) - 1
	if width == 8 {
		mask = ^uint64(0)
	}
	for _, a := range inst.Args {
		switch v := a.(type) {
		case x86asm.Imm:
			if uint64(v)&mask == value {
				return true
			}
		case x86asm.Mem:
			if v.Base == 0 && v.Index == 0 && uint64(v.Disp)&mask == value {
				return true
			}
		}
	}
	return false
}

func immRefType(inst x86asm.Inst) (string, string) {
	abs := false
	for _, a := range inst.Args {
		if m, ok := a.(x86asm.Mem); ok && m.Base == 0 && m.Index == 0 {
			abs = true
		}
	}
	how := "immediate"
	if abs {
		how = "absolute"
	}
	switch inst.Op {
	case x86asm.CALL:
		return "CALL", how
	case x86asm.JMP:
		return "JMP", how
	case x86asm.MOV:
		return "MOV", how
	case x86asm.PUSH:
		return "PUSH", how
	case x86asm.LEA:
		return "LEA", how
	}
	return "DATA", how
}

// xrefAsm renders inst in Intel syntax with the mnemonic upper-cased, as the
// decoded RIP-relative results are.
func xrefAsm(inst x86asm.Inst, va uint64) string {
	asm := x86asm.IntelSyntax(inst, va, nil)
	if split := strings.IndexByte(asm, ' '); split > 0 {
		return strings.ToUpper(asm[:split]) + asm[split:]
	}
	return strings.ToUpper(asm)
}

// indirectUse looks at the few instructions after a reference that loads the
// target address into a register (lea reg, [target] or mov reg, imm) and
// reports a following call/jmp through that register: the target is then
// called, not just addressed. It stops when the register is written again.
func indirectUse(data []byte, off int, mode int, va uint64) (string, uint64, bool) {
	inst, err := x86asm.Decode(data[off:], mode)
	if err != nil || len(inst.Args) < 2 {
		return "", 0, false
	}
	dst, ok := inst.Args[0].(x86asm.Reg)
	if !ok {
		return "", 0, false
	}
	switch inst.Op {
	case x86asm.LEA:
	case x86asm.MOV:
		if _, isImm := inst.Args[1].(x86asm.Imm); !isImm {
			return "", 0, false // mov reg, [mem] loads the stored value, not the address
		}
	default:
		return "", 0, false
	}
	at := off + inst.Len
	cur := va + uint64(inst.Len)
	for n := 0; n < 4 && at < len(data); n++ {
		next, err := x86asm.Decode(data[at:], mode)
		if err != nil {
			return "", 0, false
		}
		if next.Op == x86asm.CALL || next.Op == x86asm.JMP {
			if r, ok := next.Args[0].(x86asm.Reg); ok && sameReg(r, dst) {
				return strings.ToLower(next.Op.String()) + " " + strings.ToLower(r.String()), cur, true
			}
			return "", 0, false
		}
		if w, ok := next.Args[0].(x86asm.Reg); ok && sameReg(w, dst) && next.Op != x86asm.CMP && next.Op != x86asm.TEST && next.Op != x86asm.PUSH {
			return "", 0, false
		}
		at += next.Len
		cur += uint64(next.Len)
	}
	return "", 0, false
}

// sameReg compares registers across widths (eax and rax are one register).
func sameReg(a, b x86asm.Reg) bool {
	norm := func(r x86asm.Reg) x86asm.Reg {
		switch {
		case r >= x86asm.EAX && r <= x86asm.R15L:
			return r - x86asm.EAX + x86asm.RAX
		}
		return r
	}
	return norm(a) == norm(b)
}

// memDisp is m's displacement as a signed offset. x86asm sign-extends an
// 8-bit displacement but returns a 32-bit one zero-extended, so [rbp-0x100]
// and a backward [rip-0x39b4] come back as +0xffffff00 and +0xffffc64c.
// A base-less operand is an absolute address and is left as it is.
func memDisp(m x86asm.Mem) int64 {
	if (m.Base != 0 || m.Index != 0) && m.Disp >= 1<<31 && m.Disp < 1<<32 {
		return m.Disp - 1<<32
	}
	return m.Disp
}
