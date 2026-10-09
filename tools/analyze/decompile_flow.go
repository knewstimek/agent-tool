package analyze

import (
	"sort"

	"golang.org/x/arch/x86/x86asm"
)

// maxTailCallScan bounds the flow walk per function (instructions).
const maxTailCallScan = 20000

// tailCallOverrides finds the unconditional direct jumps out of the function
// at entry that Ghidra's Shared Return analysis turns into tail calls
// (CALL_RETURN flow overrides), so the decompiler renders `return f();`
// instead of inlining the jumped-to function's body.
//
// Ghidra rules mirrored (SharedReturnAnalysisCmd, analyzer defaults:
// unconditional jumps only, contiguous functions assumed):
//   - a jump to a known function entry other than this function's own;
//   - a forward jump at or past the next function start after the jump, or a
//     backward jump before the function start preceding it (the target is
//     made a function).
//
// A jump at a function's own entry is a thunk, which Ghidra handles
// separately, so it gets no override.
func tailCallOverrides(t *decompileTarget, entry uint64) map[uint64]string {
	mode := 32
	if t.is64 {
		mode = 64
	}
	starts := t.host.starts
	isStart := func(va uint64) bool {
		_, ok := t.host.funcs[va]
		return ok
	}
	next := func(va uint64) (uint64, bool) {
		i := sort.Search(len(starts), func(i int) bool { return starts[i] > va })
		if i == len(starts) {
			return 0, false
		}
		return starts[i], true
	}

	var out map[uint64]string
	seen := map[uint64]bool{}
	work := []uint64{entry}
	for steps := 0; len(work) > 0 && steps < maxTailCallScan; {
		va := work[len(work)-1]
		work = work[:len(work)-1]
		for !seen[va] && steps < maxTailCallScan {
			seen[va] = true
			steps++
			code, ok := t.codeAt(va)
			if !ok {
				break
			}
			inst, err := x86asm.Decode(code, mode)
			if err != nil || inst.Len == 0 {
				break
			}
			nextVA := va + uint64(inst.Len)
			target, direct := directTarget(inst, nextVA)
			switch inst.Op {
			case x86asm.RET, x86asm.LRET, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ, x86asm.HLT, x86asm.UD2:
				nextVA = 0 // terminator
			case x86asm.JMP:
				if !direct {
					// A switch: the decompiler recovers its table itself, but the
					// case blocks can hold tail jumps too.
					work = append(work, t.switchTargets(va, inst)...)
					nextVA = 0
					break
				}
				if va != entry && t.isTailJump(va, target, entry, isStart, next) {
					if out == nil {
						out = map[uint64]string{}
					}
					out[va] = "CALL_RETURN"
				} else {
					work = append(work, target)
				}
				nextVA = 0
			default:
				if direct && isCondJump(inst.Op) {
					work = append(work, target)
				}
			}
			if nextVA == 0 {
				break
			}
			va = nextVA
		}
	}
	return out
}

func (t *decompileTarget) isTailJump(src, dst, entry uint64, isStart func(uint64) bool, next func(uint64) (uint64, bool)) bool {
	if dst == entry {
		return false // a jump back to this function's own top
	}
	if isStart(dst) {
		return true
	}
	if dst > src {
		n, ok := next(src)
		return ok && dst >= n
	}
	prev, ok := t.host.precedingStart(src)
	return ok && dst < prev
}

func (t *decompileTarget) switchTargets(va uint64, inst x86asm.Inst) []uint64 {
	for _, s := range t.exec {
		if s.jt == nil || va < s.vma || va-s.vma >= uint64(len(s.data)) {
			continue
		}
		var out []uint64
		for _, off := range s.jt(inst, int(va-s.vma)) {
			out = append(out, s.vma+uint64(off))
		}
		return out
	}
	return nil
}

// codeAt returns the executable bytes from va to the end of its section.
func (t *decompileTarget) codeAt(va uint64) ([]byte, bool) {
	for _, s := range t.exec {
		if va >= s.vma && va-s.vma < uint64(len(s.data)) {
			return s.data[va-s.vma:], true
		}
	}
	return nil, false
}

// directTarget is the destination of a relative branch or call.
func directTarget(inst x86asm.Inst, nextVA uint64) (uint64, bool) {
	rel, ok := inst.Args[0].(x86asm.Rel)
	if !ok {
		return 0, false
	}
	return uint64(int64(nextVA) + int64(rel)), true
}

func isCondJump(op x86asm.Op) bool {
	switch op {
	case x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE, x86asm.JE, x86asm.JG, x86asm.JGE, x86asm.JL,
		x86asm.JLE, x86asm.JNE, x86asm.JNO, x86asm.JNP, x86asm.JNS, x86asm.JO, x86asm.JP, x86asm.JS,
		x86asm.JCXZ, x86asm.JECXZ, x86asm.JRCXZ, x86asm.LOOP, x86asm.LOOPE, x86asm.LOOPNE:
		return true
	}
	return false
}
