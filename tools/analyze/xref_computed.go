package analyze

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// Computed references: addresses no single instruction spells out.

// collectXrefImageBase finds x64 data references made through the image
// base: MSVC loads __ImageBase (lea r, [rip+d] with the image base as the
// target) and then addresses tables and arrays as [r + index*scale + RVA].
// From each such lea the next instructions are followed until r is written
// again.
func collectXrefImageBase(bin *xrefBinary, target xrefTargetRange, reported map[uint64]bool, maxRes, found int, refs []xrefResult) ([]xrefResult, int) {
	if bin.arch != "x64" || bin.format != "PE" {
		return refs, found
	}
	for _, sec := range bin.sections {
		data := sec.data
		for i := 0; i+7 <= len(data) && found < maxRes; i++ {
			// REX.W lea r, [rip+disp32]: 48/4C 8D, ModRM mod=00 r/m=101.
			if (data[i] != 0x48 && data[i] != 0x4C) || data[i+1] != 0x8D || data[i+2]&0xC7 != 0x05 {
				continue
			}
			lea, err := x86asm.Decode(data[i:], 64)
			if err != nil || lea.Op != x86asm.LEA {
				continue
			}
			m := lea.Args[1].(x86asm.Mem)
			leaVA := bin.imageBase + uint64(sec.rva) + uint64(i)
			if leaVA+uint64(lea.Len)+uint64(memDisp(m)) != bin.imageBase {
				continue
			}
			reg := regArg(lea, 0)
			p := i + lea.Len
			for n := 0; n < 24 && p < len(data) && found < maxRes; n++ {
				in, err := x86asm.Decode(data[p:], 64)
				if err != nil || in.Len == 0 {
					break
				}
				va := bin.imageBase + uint64(sec.rva) + uint64(p)
				for _, a := range in.Args {
					mm, ok := a.(x86asm.Mem)
					if !ok || mm.Base != reg {
						continue
					}
					if t := bin.imageBase + uint64(memDisp(mm)); target.containsVA(t) && !reported[va] {
						reported[va] = true
						refs = append(refs, xrefResult{refType: "DATA", line: fmt.Sprintf("  0x%x: %s  (image base + 0x%x, base loaded at 0x%x)\n",
							va, xrefAsm(in, va), uint64(memDisp(mm)), leaVA)})
						found++
					}
				}
				if w := regArg(in, 0); w != 0 && sameReg(w, reg) && in.Op != x86asm.CMP && in.Op != x86asm.TEST {
					break
				}
				if in.Op == x86asm.RET || in.Op == x86asm.JMP || in.Op == x86asm.CALL {
					break
				}
				p += in.Len
			}
		}
	}
	return refs, found
}

// collectXrefSwitchCases reports the switch dispatches whose case table
// leads to the target: a case block is reached through a table entry, not
// through an instruction that names it.
func collectXrefSwitchCases(bin *xrefBinary, target xrefTargetRange, reported map[uint64]bool, maxRes, found int, refs []xrefResult) ([]xrefResult, int) {
	mode := map[string]int{"x86": 32, "x64": 64}[bin.arch]
	if mode == 0 {
		return refs, found
	}
	var execs, statics []cgSection
	for _, s := range bin.sections {
		execs = append(execs, cgSection{rva: s.rva, data: s.data})
	}
	for _, s := range bin.dataSections {
		statics = append(statics, cgSection{rva: s.rva, data: s.data})
	}
	read := readerFor(bin.imageBase, execs, statics)
	inCode := func(va uint64) bool {
		return va >= bin.imageBase && va-bin.imageBase <= 0xFFFFFFFF && isInExecSection(execs, uint32(va-bin.imageBase))
	}
	for _, sec := range bin.sections {
		data := sec.data
		baseVA := bin.imageBase + uint64(sec.rva)
		for i := 0; i+2 <= len(data) && found < maxRes; i++ {
			// jmp r/m: FF /4 (with a REX prefix before it in x64).
			if data[i] != 0xFF || data[i+1]&0x38 != 0x20 {
				continue
			}
			pos := i
			if mode == 64 && i > 0 && data[i-1]&0xF0 == 0x40 {
				pos = i - 1
			}
			jmp, err := x86asm.Decode(data[pos:], mode)
			if err != nil || jmp.Op != x86asm.JMP || !isSwitchJump(jmp) {
				continue
			}
			for k, c := range switchCases(data, baseVA, pos, jmp, mode, read, inCode) {
				va := baseVA + uint64(pos)
				if target.containsVA(c) && !reported[va] {
					reported[va] = true
					refs = append(refs, xrefResult{refType: "JMP", line: fmt.Sprintf("  0x%x: %s  (switch case %d -> 0x%x)\n", va, xrefAsm(jmp, va), k, c)})
					found++
				}
			}
		}
	}
	return refs, found
}
