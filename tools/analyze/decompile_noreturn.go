package analyze

import (
	"runtime"
	"strings"
	"sync"

	"golang.org/x/arch/x86/x86asm"
)

// Functions that never return, by name, from Ghidra's analyzer data
// (Ghidra/Features/Base/data/*FunctionsThatDoNotReturn, Apache-2.0). Names
// are compared with leading underscores removed, as Ghidra's "Non-Returning
// Functions - Known" analyzer does.
var noReturnNamesPE = []string{
	"abort", "CxxThrowException", "CxxThrowException@8", "CxxFrameHandler3", "crtExitProcess", "ExitProcess",
	"ExitThread", "exit", "ExRaiseAccessViolation", "ExRaiseDatatypeMisalignment", "ExRaiseStatus",
	"FreeLibraryAndExitThread", "invalid_parameter_noinfo_noreturn", "invoke_watson", "KeBugCheck",
	"KeBugCheckEx", "longjmp", "quick_exit", "RpcRaiseException", "terminate", "raise_securityfailure",
	"report_rangecheckfailure", "?_Xregex_error@std@@YAXW4error_type@regex_constant@1@@Z",
	"?_Xbad_alloc@std@@YAXXZ", "?_Xlength_error@std@@YAXPBD@Z", "?_Xout_of_range@std@@YAXPBD@Z",
	"?_Xbad_function_call@std@@YAXXZ", "?terminate@@YAXXZ",
}

var noReturnNamesELF = []string{
	"exit", "cexit", "c_exit", "abort", "reboot", "longjmp", "longjmp_chk", "siglongjmp", "panic",
	"stack_chk_fail", "cxa_throw", "cxa_terminate", "cxa_call_unexpected", "cxa_bad_cast", "Unwind_Resume",
	"assert_fail", "assert_rtn", "fortify_fail", "ZSt9terminatev", "ZN10__cxxabiv111__terminateEPFvvE",
}

// noReturnThreshold is how many call sites must look like the callee never
// returns before it is believed (Ghidra's "Function Non-return Threshold"
// default).
const noReturnThreshold = 3

func knownNoReturn(name string, elf bool) bool {
	n := strings.TrimLeft(name, "_")
	list := noReturnNamesPE
	if elf {
		list = noReturnNamesELF
	}
	for _, x := range list {
		if strings.TrimLeft(x, "_") == n {
			return true
		}
	}
	return false
}

// callSite is a direct call found by walking the program's functions.
type callSite struct {
	at, target, fallthru uint64
}

// discoverNoReturn finds functions that never return, as Ghidra's
// "Non-Returning Functions - Discovered" analyzer does
// (FindNoReturnFunctionsAnalyzer): a callee is non-returning when at least
// noReturnThreshold of its call sites are followed by something that is not
// the call's continuation -- the start of another function, undecodable
// bytes, or INT3 alignment padding -- or when it was suspected once and every
// path through it ends in a call to a non-returning function. Each new
// non-returning function can expose more, so the search repeats.
func (t *decompileTarget) discoverNoReturn(seed map[uint64]bool) map[uint64]bool {
	noRet := map[uint64]bool{}
	for va := range seed {
		noRet[va] = true
	}
	suspicious := t.suspiciousSites()
	for round := 0; round < 16; round++ {
		evidence := map[uint64]int{}
		for _, s := range suspicious {
			if !noRet[s.target] {
				evidence[s.target]++
			}
		}
		added := false
		for target, n := range evidence {
			if n >= noReturnThreshold || t.onlyCallsNoReturn(target, noRet) {
				noRet[target] = true
				added = true
			}
		}
		if !added {
			break
		}
	}
	return noRet
}

// suspiciousSites walks every known function's flow and returns its direct
// calls to known function starts that Ghidra's indicators flag (see
// notContinuation). A site's indication depends only on the code and the
// function starts, so it is decided once. Decoding every instruction of a
// large program dominates the worker's start-up, so the starts are split
// across goroutines: each walks a contiguous range with its own visited set
// (functions rarely overlap; a site found twice is kept once).
func (t *decompileTarget) suspiciousSites() []callSite {
	starts := t.host.starts
	n := runtime.GOMAXPROCS(0)
	if n > 16 {
		n = 16
	}
	if len(starts) < 1000 {
		n = 1
	}
	parts := make([][]callSite, n)
	var wg sync.WaitGroup
	for w := 0; w < n; w++ {
		lo, hi := len(starts)*w/n, len(starts)*(w+1)/n
		wg.Add(1)
		go func(w int, starts []uint64) {
			defer wg.Done()
			for _, s := range t.callSites(starts) {
				if t.notContinuation(s.fallthru) {
					parts[w] = append(parts[w], s)
				}
			}
		}(w, starts[lo:hi])
	}
	wg.Wait()
	seen := map[uint64]bool{}
	var out []callSite
	for _, p := range parts {
		for _, s := range p {
			if !seen[s.at] {
				seen[s.at] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// callSites walks the flow of the functions at starts and records their
// direct calls to known function starts.
func (t *decompileTarget) callSites(starts []uint64) []callSite {
	mode := 32
	if t.is64 {
		mode = 64
	}
	var out []callSite
	// One bit per code byte: a map entry per instruction made this walk
	// several times slower on a large program (millions of instructions).
	seen := make([][]uint64, len(t.exec))
	for i, s := range t.exec {
		seen[i] = make([]uint64, len(s.data)/64+1)
	}
	visit := func(va uint64) bool { // reports whether va was new
		for i, s := range t.exec {
			if va >= s.vma && va-s.vma < uint64(len(s.data)) {
				off := va - s.vma
				w, b := &seen[i][off/64], uint64(1)<<(off%64)
				if *w&b != 0 {
					return false
				}
				*w |= b
				return true
			}
		}
		return false
	}
	for _, start := range starts {
		work := []uint64{start}
		for len(work) > 0 {
			va := work[len(work)-1]
			work = work[:len(work)-1]
			for steps := 0; steps < 100000 && visit(va); steps++ {
				code, ok := t.codeAt(va)
				if !ok {
					break
				}
				inst, err := x86asm.Decode(code, mode)
				if err != nil || inst.Len == 0 {
					break
				}
				next := va + uint64(inst.Len)
				target, direct := directTarget(inst, next)
				stop := false
				switch inst.Op {
				case x86asm.RET, x86asm.LRET, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ, x86asm.HLT, x86asm.UD2:
					stop = true
				case x86asm.JMP:
					if direct {
						if _, isFunc := t.host.funcs[target]; !isFunc {
							work = append(work, target)
						}
					} else {
						work = append(work, t.switchTargets(va, inst)...)
					}
					stop = true
				case x86asm.CALL:
					if direct {
						if _, isFunc := t.host.funcs[target]; isFunc {
							out = append(out, callSite{at: va, target: target, fallthru: next})
						}
					}
				default:
					if direct && isCondJump(inst.Op) {
						work = append(work, target)
					}
				}
				if stop {
					break
				}
				va = next
			}
		}
	}
	return out
}

// notContinuation reports Ghidra's indications that the code after a call
// is not where the call returns to: the start of another function, bytes
// that do not decode, or INT3 padding -- checked along the straight-line
// instructions that follow.
func (t *decompileTarget) notContinuation(va uint64) bool {
	mode := 32
	if t.is64 {
		mode = 64
	}
	for i := 0; i < 32; i++ {
		if _, isFunc := t.host.funcs[va]; isFunc {
			return true
		}
		code, ok := t.codeAt(va)
		if !ok {
			return true // falls out of code
		}
		if code[0] == 0xcc {
			return true
		}
		inst, err := x86asm.Decode(code, mode)
		if err != nil || inst.Len == 0 {
			return true
		}
		switch inst.Op {
		case x86asm.CALL, x86asm.JMP, x86asm.RET, x86asm.LRET, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ,
			x86asm.HLT, x86asm.UD2, x86asm.INT:
			return false
		}
		if _, direct := directTarget(inst, va+uint64(inst.Len)); direct {
			return false // a conditional branch ends the straight line
		}
		va += uint64(inst.Len)
	}
	return false
}

// onlyCallsNoReturn reports that every path through the function at start
// ends in a call or jump to a non-returning function (Ghidra's
// targetOnlyCallsNoReturn): no return is reachable, and at least one
// non-returning callee is.
func (t *decompileTarget) onlyCallsNoReturn(start uint64, noRet map[uint64]bool) bool {
	mode := 32
	if t.is64 {
		mode = 64
	}
	hit := false
	seen := map[uint64]bool{}
	work := []uint64{start}
	for steps := 0; len(work) > 0; {
		va := work[len(work)-1]
		work = work[:len(work)-1]
		for !seen[va] {
			if steps++; steps > 20000 {
				return false
			}
			seen[va] = true
			code, ok := t.codeAt(va)
			if !ok {
				return false
			}
			inst, err := x86asm.Decode(code, mode)
			if err != nil || inst.Len == 0 {
				return false
			}
			next := va + uint64(inst.Len)
			target, direct := directTarget(inst, next)
			switch inst.Op {
			case x86asm.RET, x86asm.LRET, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ:
				return false
			case x86asm.HLT, x86asm.UD2, x86asm.INT:
				return false // a terminal block without a non-returning call
			case x86asm.CALL:
				if direct && noRet[target] {
					hit = true
					next = 0 // the path ends here
				}
			case x86asm.JMP:
				switch {
				case !direct:
					return false // an indirect jump may return through a table
				case noRet[target]:
					hit = true
				default:
					if _, isFunc := t.host.funcs[target]; isFunc {
						return false // a tail call to a returning function
					}
					work = append(work, target)
				}
				next = 0
			default:
				if direct && isCondJump(inst.Op) {
					work = append(work, target)
				}
			}
			if next == 0 {
				break
			}
			va = next
		}
	}
	return hit
}
