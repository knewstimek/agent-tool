package analyze

// Semantic x86/x64 instruction search and bounded value tracing.
//
// Unlike pattern_search, this operation compares decoded operands rather than
// byte spellings. It deliberately has two discovery lanes:
//   - instructions reached by a function-start-anchored CFG walk are confirmed;
//   - matching decodes found only by an every-byte executable-section sweep are
//     candidates, so a desynchronised linear sweep cannot hide real code while
//     embedded data is never presented as equally trustworthy.

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/arch/x86/x86asm"
)

const (
	defaultInstructionSearchResults = 200
	maxInstructionSearchResults     = 1000
	instructionSearchBudget         = 40_000_000
	maxAbstractConstants            = 8
)

type instructionSearchSpec struct {
	mnemonic     string
	regFamily    int
	regWidth     int
	hasRegister  bool
	immediate    uint64
	hasImmediate bool
	displacement int64
	hasDisp      bool
	callTarget   string
	findings     string
}

type instructionHit struct {
	rva        uint32
	text       string
	confidence string
}

type valueTraceHit struct {
	rva      uint32
	text     string
	possible bool
	kind     string
}

func opInstructionSearch(input AnalyzeInput) (string, error) {
	spec, err := parseInstructionSearchSpec(input)
	if err != nil {
		return "", err
	}

	bin, err := cgOpenBinary(input.FilePath)
	if err != nil {
		return "", err
	}
	if bin.closer != nil {
		defer bin.closer()
	}
	if bin.arch != "x86" && bin.arch != "x64" {
		return "", fmt.Errorf("instruction_search currently supports x86/x64 binaries (got %s)", bin.arch)
	}

	maxResults := input.MaxResults
	if maxResults <= 0 {
		maxResults = defaultInstructionSearchResults
	}
	if maxResults > maxInstructionSearchResults {
		maxResults = maxInstructionSearchResults
	}

	traceValues := spec.hasImmediate
	if input.TraceValues != nil {
		traceValues = *input.TraceValues
	}

	reachable, interiors, traces, budgetComplete := analyzeInstructionFlows(bin, spec, traceValues, maxResults)
	var hits []instructionHit
	var totalMatches int
	showDirect := spec.findings != "call"
	if showDirect {
		hits, totalMatches = exhaustiveInstructionMatches(bin, spec, reachable, interiors, maxResults)
	}

	// Name the function of each hit (PDB, export and symbol names, else sub_).
	loc := &xrefLocator{imageBase: bin.imageBase, funcs: bin.funcTable, symbols: bin.symbols}
	where := func(rva uint32) string {
		if name, _ := loc.function(bin.imageBase + uint64(rva)); name != "" {
			return "  ; in " + name
		}
		return ""
	}

	var sb strings.Builder
	sb.WriteString("Instruction search: " + formatInstructionFilter(spec) + "\n")

	if showDirect && len(hits) == 0 {
		sb.WriteString("Direct instruction matches: none\n")
	} else if showDirect {
		sb.WriteString(fmt.Sprintf("Direct instruction matches (%d shown", len(hits)))
		if totalMatches > len(hits) {
			sb.WriteString(fmt.Sprintf(", %d total", totalMatches))
		}
		sb.WriteString("):\n")
		for _, hit := range hits {
			va := bin.imageBase + uint64(hit.rva)
			sb.WriteString(fmt.Sprintf("  [%s] 0x%x: %s%s\n", hit.confidence, va, hit.text, where(hit.rva)))
		}
		for _, hit := range hits {
			if hit.confidence == "candidate" {
				sb.WriteString("  candidate = exhaustive executable-byte recovery; may be indirect code or embedded data\n")
				break
			}
		}
	}

	if traceValues {
		if showDirect {
			sb.WriteString("\n")
		}
		sb.WriteString("Value-flow findings:\n")
		if len(traces) == 0 {
			sb.WriteString(fmt.Sprintf("  none for 0x%x\n", spec.immediate))
		} else {
			for _, hit := range traces {
				confidence := "confirmed"
				if hit.possible {
					confidence = "possible"
				}
				sb.WriteString(fmt.Sprintf("  [%s] 0x%x: %s%s\n", confidence,
					bin.imageBase+uint64(hit.rva), hit.text, where(hit.rva)))
			}
		}
	}
	if !budgetComplete {
		sb.WriteString("\n** partial analysis: CFG confidence/value traces may be incomplete (decode budget exhausted)")
		if showDirect {
			sb.WriteString("; direct exhaustive matches remain complete up to max_results")
		}
		sb.WriteString(" **\n")
	}
	if totalMatches > maxResults {
		sb.WriteString(fmt.Sprintf("\n(direct results truncated at max_results=%d; %d matches found)\n", maxResults, totalMatches))
	}
	return sb.String(), nil
}

func parseInstructionSearchSpec(input AnalyzeInput) (instructionSearchSpec, error) {
	spec := instructionSearchSpec{
		mnemonic:   strings.ToUpper(strings.TrimSpace(input.Mnemonic)),
		callTarget: strings.ToLower(strings.TrimSpace(input.CallTarget)),
		findings:   strings.ToLower(strings.TrimSpace(input.Findings)),
	}
	if spec.findings == "" {
		spec.findings = "all"
		if spec.callTarget != "" {
			spec.findings = "call"
		}
	}
	if spec.findings != "all" && spec.findings != "call" && spec.findings != "producer" {
		return spec, fmt.Errorf("findings must be all, call, or producer")
	}
	if input.Register != "" {
		family, width, ok := parseGPRName(input.Register)
		if !ok {
			return spec, fmt.Errorf("unsupported register %q (instruction_search currently accepts x86/x64 general-purpose registers)", input.Register)
		}
		spec.regFamily, spec.regWidth, spec.hasRegister = family, width, true
	}
	if strings.TrimSpace(input.Immediate) != "" {
		value, err := parseInstructionImmediate(input.Immediate)
		if err != nil {
			return spec, err
		}
		spec.immediate, spec.hasImmediate = value, true
	}
	if strings.TrimSpace(input.Displacement) != "" {
		value, err := parseInstructionImmediate(input.Displacement)
		if err != nil {
			return spec, fmt.Errorf("invalid displacement %q", input.Displacement)
		}
		spec.displacement, spec.hasDisp = int64(value), true
	}
	if spec.mnemonic == "" && !spec.hasRegister && !spec.hasImmediate && !spec.hasDisp {
		return spec, fmt.Errorf("instruction_search requires at least one of mnemonic, register, immediate, or displacement")
	}
	if input.TraceValues != nil && *input.TraceValues && !spec.hasImmediate {
		return spec, fmt.Errorf("trace_values requires immediate")
	}
	if spec.callTarget != "" && !spec.hasImmediate {
		return spec, fmt.Errorf("call_target requires immediate")
	}
	if spec.callTarget != "" && input.TraceValues != nil && !*input.TraceValues {
		return spec, fmt.Errorf("call_target requires trace_values")
	}
	if spec.findings == "call" && !spec.hasImmediate {
		return spec, fmt.Errorf("findings=call requires immediate")
	}
	return spec, nil
}

func parseInstructionImmediate(raw string) (uint64, error) {
	s := strings.TrimSpace(raw)
	base := 10
	digits := s
	if strings.HasPrefix(strings.ToLower(digits), "0x") {
		base = 16
		digits = digits[2:]
	}
	if strings.HasPrefix(s, "-") {
		digits = s[1:]
		if strings.HasPrefix(strings.ToLower(digits), "0x") {
			base = 16
			digits = digits[2:]
		}
		v, err := strconv.ParseInt(digits, base, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid immediate %q", raw)
		}
		return uint64(-v), nil
	}
	v, err := strconv.ParseUint(digits, base, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid immediate %q", raw)
	}
	return v, nil
}

func formatInstructionFilter(spec instructionSearchSpec) string {
	var parts []string
	if spec.mnemonic != "" {
		parts = append(parts, "mnemonic="+spec.mnemonic)
	}
	if spec.hasRegister {
		parts = append(parts, "register="+gprDisplayName(spec.regFamily, spec.regWidth))
	}
	if spec.hasImmediate {
		parts = append(parts, fmt.Sprintf("immediate=0x%x", spec.immediate))
	}
	if spec.hasDisp {
		parts = append(parts, fmt.Sprintf("displacement=%#x", spec.displacement))
	}
	if spec.callTarget != "" {
		parts = append(parts, "call_target="+spec.callTarget)
	}
	if spec.findings != "all" {
		parts = append(parts, "findings="+spec.findings)
	}
	return strings.Join(parts, ", ")
}

func exhaustiveInstructionMatches(bin *cgBinary, spec instructionSearchSpec, reachable, interiors *rvaBits, maxResults int) ([]instructionHit, int) {
	mode := 32
	if bin.is64 {
		mode = 64
	}
	// Every executable byte is a possible instruction start; the sections are
	// cut into chunks decoded in parallel (a decode may read past its chunk).
	type chunk struct {
		sec    cgSection
		lo, hi int
	}
	var chunks []chunk
	const chunkSize = 1 << 20
	for _, sec := range bin.execSections {
		for lo := 0; lo < len(sec.data); lo += chunkSize {
			chunks = append(chunks, chunk{sec, lo, min(lo+chunkSize, len(sec.data))})
		}
	}
	type part struct {
		confirmed, candidates []instructionHit
		total                 int
	}
	parts := make([]part, len(chunks))
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < analysisThreads(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= len(chunks) {
					return
				}
				c, out := chunks[i], &parts[i]
				for off := c.lo; off < c.hi; off++ {
					rva := c.sec.rva + uint32(off)
					// A byte inside a CFG-confirmed instruction cannot independently be
					// another instruction start. This removes REX-prefix false duplicates
					// and immediate bytes that happen to decode as plausible opcodes.
					if interiors.has(rva) {
						continue
					}
					inst, err := x86asm.Decode(c.sec.data[off:], mode)
					if err != nil || inst.Len <= 0 || !instructionMatches(inst, spec) {
						continue
					}
					out.total++
					hit := instructionHit{rva: rva, text: x86asm.IntelSyntax(inst, bin.imageBase+uint64(rva), nil), confidence: "candidate"}
					if reachable.has(rva) {
						hit.confidence = "confirmed"
						if len(out.confirmed) < maxResults {
							out.confirmed = append(out.confirmed, hit)
						}
					} else if len(out.candidates) < maxResults {
						out.candidates = append(out.candidates, hit)
					}
				}
			}
		}()
	}
	wg.Wait()
	var confirmed, candidates []instructionHit
	total := 0
	for _, p := range parts {
		confirmed = append(confirmed, p.confirmed...)
		candidates = append(candidates, p.candidates...)
		total += p.total
	}
	sort.Slice(confirmed, func(i, j int) bool { return confirmed[i].rva < confirmed[j].rva })
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].rva < candidates[j].rva })
	hits := append([]instructionHit(nil), confirmed[:min(len(confirmed), maxResults)]...)
	remaining := min(maxResults-len(hits), len(candidates))
	hits = append(hits, candidates[:remaining]...)
	return hits, total
}

func instructionMatches(inst x86asm.Inst, spec instructionSearchSpec) bool {
	if spec.mnemonic != "" && !strings.EqualFold(inst.Op.String(), spec.mnemonic) {
		return false
	}
	if spec.hasRegister {
		matched := false
		for _, arg := range inst.Args {
			reg, ok := arg.(x86asm.Reg)
			if !ok {
				continue
			}
			family, width, _, ok := gprDescriptor(reg)
			if ok && family == spec.regFamily && width == spec.regWidth {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if spec.hasDisp {
		// [base+index*scale+disp] through a register. Stack-pointer bases are
		// locals and arguments, RIP-relative operands a distance to data:
		// neither is a structure offset.
		matched := false
		for _, arg := range inst.Args {
			if m, ok := arg.(x86asm.Mem); ok && memDisp(m) == spec.displacement && (m.Base != 0 || m.Index != 0) && !isStackOrRIP(m.Base) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if spec.hasImmediate {
		matched := false
		for _, arg := range inst.Args {
			if imm, ok := arg.(x86asm.Imm); ok && immediateEquivalent(uint64(int64(imm)), spec.immediate, inst.DataSize) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func isStackOrRIP(r x86asm.Reg) bool {
	return r == x86asm.RSP || r == x86asm.ESP || r == x86asm.RIP
}

func immediateEquivalent(actual, wanted uint64, dataSize int) bool {
	if actual == wanted {
		return true
	}
	if dataSize <= 0 || dataSize >= 64 {
		return false
	}
	mask := uint64(1)<<uint(dataSize) - 1
	return actual&mask == wanted&mask
}

// abstractValue is either a bounded set of constants or a symbolic address
// relative to the function-entry stack pointer. Unknown is the zero value.
type abstractValue struct {
	kind   uint8 // 0 unknown, 1 constants, 2 stack-relative
	consts []uint64
	stack  int64
}

type abstractState struct {
	regs  [16]abstractValue
	stack map[int64]abstractValue
}

func unknownValue() abstractValue { return abstractValue{} }

func constantValue(v uint64) abstractValue {
	return abstractValue{kind: 1, consts: []uint64{v}}
}

func stackValue(off int64) abstractValue { return abstractValue{kind: 2, stack: off} }

func (v abstractValue) clone() abstractValue {
	out := v
	if v.consts != nil {
		out.consts = append([]uint64(nil), v.consts...)
	}
	return out
}

func (v abstractValue) contains(target uint64) bool {
	if v.kind != 1 {
		return false
	}
	for _, c := range v.consts {
		if c == target {
			return true
		}
	}
	return false
}

func (v abstractValue) possible(target uint64) bool {
	return v.contains(target) && len(v.consts) > 1
}

func newAbstractState(is64 bool) abstractState {
	s := abstractState{stack: make(map[int64]abstractValue)}
	if is64 {
		s.regs[4] = stackValue(0) // RSP
	} else {
		s.regs[4] = stackValue(0) // ESP
	}
	return s
}

func (s abstractState) clone() abstractState {
	out := abstractState{stack: make(map[int64]abstractValue, len(s.stack))}
	for i := range s.regs {
		out.regs[i] = s.regs[i].clone()
	}
	for k, v := range s.stack {
		out.stack[k] = v.clone()
	}
	return out
}

func mergeAbstractState(dst *abstractState, src abstractState) bool {
	changed := false
	for i := range dst.regs {
		merged := mergeAbstractValue(dst.regs[i], src.regs[i])
		if !abstractValueEqual(dst.regs[i], merged) {
			dst.regs[i] = merged
			changed = true
		}
	}
	for k, old := range dst.stack {
		other, ok := src.stack[k]
		if !ok {
			delete(dst.stack, k)
			changed = true
			continue
		}
		merged := mergeAbstractValue(old, other)
		if merged.kind == 0 {
			delete(dst.stack, k)
			changed = true
		} else if !abstractValueEqual(old, merged) {
			dst.stack[k] = merged
			changed = true
		}
	}
	return changed
}

func mergeAbstractValue(a, b abstractValue) abstractValue {
	if a.kind == 0 || b.kind == 0 || a.kind != b.kind {
		return unknownValue()
	}
	if a.kind == 2 {
		if a.stack == b.stack {
			return a
		}
		return unknownValue()
	}
	set := make(map[uint64]bool, len(a.consts)+len(b.consts))
	for _, v := range a.consts {
		set[v] = true
	}
	for _, v := range b.consts {
		set[v] = true
	}
	if len(set) > maxAbstractConstants {
		return unknownValue()
	}
	vals := make([]uint64, 0, len(set))
	for v := range set {
		vals = append(vals, v)
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	return abstractValue{kind: 1, consts: vals}
}

func abstractValueEqual(a, b abstractValue) bool {
	if a.kind != b.kind || a.stack != b.stack || len(a.consts) != len(b.consts) {
		return false
	}
	for i := range a.consts {
		if a.consts[i] != b.consts[i] {
			return false
		}
	}
	return true
}

// rvaBits is a set of RVAs within the executable sections, one bit per byte:
// the reached-instruction and instruction-interior sets cover every decoded
// instruction of the binary, too many for maps. Safe for concurrent set.
type rvaBits struct {
	secs []cgSection
	bits [][]uint64
}

func newRVABits(secs []cgSection) *rvaBits {
	b := &rvaBits{secs: secs, bits: make([][]uint64, len(secs))}
	for i, s := range secs {
		b.bits[i] = make([]uint64, (len(s.data)+63)/64)
	}
	return b
}

func (b *rvaBits) locate(rva uint32) (int, int) {
	for i, s := range b.secs {
		if rva >= s.rva && uint64(rva) < uint64(s.rva)+uint64(len(s.data)) {
			return i, int(rva - s.rva)
		}
	}
	return -1, 0
}

func (b *rvaBits) set(rva uint32) {
	if i, off := b.locate(rva); i >= 0 {
		atomic.OrUint64(&b.bits[i][off/64], 1<<(off%64))
	}
}

func (b *rvaBits) has(rva uint32) bool {
	i, off := b.locate(rva)
	return i >= 0 && atomic.LoadUint64(&b.bits[i][off/64])&(1<<(off%64)) != 0
}

func (b *rvaBits) count() int {
	n := 0
	for _, s := range b.bits {
		for _, w := range s {
			n += bits.OnesCount64(w)
		}
	}
	return n
}

// analyzeInstructionFlows walks every known function's control flow,
// recording reached instructions and, with trace, the value-flow findings
// for spec.immediate. Functions are independent and spread over
// analysisThreads() workers; the decode budget is shared.
func analyzeInstructionFlows(bin *cgBinary, spec instructionSearchSpec, trace bool, maxResults int) (*rvaBits, *rvaBits, []valueTraceHit, bool) {
	reachable := newRVABits(bin.execSections)
	interiors := newRVABits(bin.execSections)
	starts := make(map[uint32]bool, len(bin.funcTable))
	frags := map[uint32][]funcRange{} // owner -> its split-off cold blocks
	for _, fn := range bin.funcTable {
		if fn.owner == 0 { // a chained fragment continues its owner
			starts[fn.begin] = true
		} else {
			frags[fn.owner] = append(frags[fn.owner], fn)
		}
	}
	var budget atomic.Int64
	budget.Store(instructionSearchBudget)
	mode := 32
	if bin.is64 {
		mode = 64
	}

	workers := analysisThreads()
	results := make([]*traceCollector, workers)
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		tc := newTraceCollector(spec, maxResults)
		results[w] = tc
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= len(bin.funcTable) || budget.Load() <= 0 {
					return
				}
				fn := bin.funcTable[i]
				if fn.owner != 0 {
					continue
				}
				walkFunctionFlow(bin, fn, frags[fn.begin], mode, starts, &budget, reachable, interiors, spec, trace, tc)
			}
		}()
	}
	wg.Wait()

	// Merge: a finding seen by several workers (overlapping bounds) is
	// possible if any saw it as possible.
	merged := map[string]int{}
	var traces []valueTraceHit
	for _, tc := range results {
		for _, h := range tc.traces {
			key := fmt.Sprintf("%x:%s", h.rva, h.text)
			if i, ok := merged[key]; ok {
				traces[i].possible = traces[i].possible || h.possible
				continue
			}
			merged[key] = len(traces)
			traces = append(traces, h)
		}
	}
	sort.Slice(traces, func(i, j int) bool {
		if traces[i].rva == traces[j].rva {
			return traces[i].text < traces[j].text
		}
		return traces[i].rva < traces[j].rva
	})
	if len(traces) > maxResults {
		traces = traces[:maxResults]
	}
	return reachable, interiors, traces, budget.Load() > 0
}

// traceCollector gathers one worker's value-flow findings. Findings come
// from two passes per function: the fixpoint pass sees states before loops
// have widened them, and what it alone finds is kept as possible (a value
// some iteration or path holds); the final pass runs on the converged states
// and decides confirmed versus possible.
type traceCollector struct {
	spec      instructionSearchSpec
	max       int
	traces    []valueTraceHit
	index     map[string]int
	settled   map[string]bool
	finalPass bool
}

func newTraceCollector(spec instructionSearchSpec, max int) *traceCollector {
	return &traceCollector{spec: spec, max: max, index: map[string]int{}, settled: map[string]bool{}}
}

func (c *traceCollector) add(rva uint32, text string, possible bool, kind string) {
	if (c.spec.findings == "call" && kind != "call") || (c.spec.findings == "producer" && kind != "producer") {
		return
	}
	key := fmt.Sprintf("%x:%s", rva, text)
	index, exists := c.index[key]
	switch {
	case exists && c.finalPass && !c.settled[key]:
		c.traces[index].possible = possible
		c.settled[key] = true
	case exists && c.finalPass:
		// Several converged blocks may reach it with different values.
		c.traces[index].possible = c.traces[index].possible || possible
	case exists:
	case len(c.traces) < c.max:
		c.index[key] = len(c.traces)
		c.traces = append(c.traces, valueTraceHit{rva: rva, text: text, possible: possible || !c.finalPass, kind: kind})
		c.settled[key] = c.finalPass
	}
}

// walkFunctionFlow decodes one function's reachable instructions and, with
// trace, runs its abstract states to a fixpoint and reports on them.
func walkFunctionFlow(bin *cgBinary, fn funcRange, frags []funcRange, mode int, starts map[uint32]bool, budget *atomic.Int64,
	reachable, interiors *rvaBits, spec instructionSearchSpec, trace bool, tc *traceCollector) {
	sec := sectionContainingRVA(bin.execSections, fn.begin)
	if sec == nil {
		return
	}
	start := int(fn.begin - sec.rva)
	end := min(int(fn.end-sec.rva), len(sec.data))
	if start < 0 || start >= end {
		return
	}
	// The body is the function's range plus its split-off cold blocks in the
	// same section, which its branches jump into and back from.
	ranges := [][2]int{{start, end}}
	for _, f := range frags {
		if f.begin >= sec.rva && uint64(f.end) <= uint64(sec.rva)+uint64(len(sec.data)) {
			ranges = append(ranges, [2]int{int(f.begin - sec.rva), int(f.end - sec.rva)})
		}
	}
	read := readerFor(bin.imageBase, bin.execSections, bin.staticSections)
	inCode := func(va uint64) bool {
		return va >= bin.imageBase && va-bin.imageBase <= 0xFFFFFFFF && isInExecSection(bin.execSections, uint32(va-bin.imageBase))
	}
	baseVA := bin.imageBase + uint64(sec.rva)
	cases := func(pos int, inst x86asm.Inst) []int {
		var out []int
		for _, va := range switchCases(sec.data, baseVA, pos, inst, mode, read, inCode) {
			if va >= baseVA && va-baseVA < uint64(len(sec.data)) {
				out = append(out, int(va-baseVA))
			}
		}
		return out
	}
	insts, leaders, switches := functionBlocks(sec.data, start, ranges, mode, sec.rva, starts, budget, cases)
	for pos, inst := range insts {
		rva := sec.rva + uint32(pos)
		reachable.set(rva)
		for byteOff := 1; byteOff < inst.Len; byteOff++ {
			interiors.set(rva + uint32(byteOff))
		}
	}
	if !trace || !spec.hasImmediate {
		return
	}

	// Abstract states are kept per basic block: a block's instructions have
	// one predecessor each, so the state runs through them in place and is
	// copied and merged only at block edges.
	states := map[int]abstractState{start: newAbstractState(bin.is64)}
	runBlock := func(leader int) (abstractState, []int) {
		st := states[leader].clone()
		for pos := leader; ; {
			inst, ok := insts[pos]
			if !ok {
				return st, nil
			}
			rva := sec.rva + uint32(pos)
			if inst.Op == x86asm.CALL || inst.Op == x86asm.LCALL {
				for _, fact := range callArgumentFacts(inst, st, bin, rva, spec.immediate, "call", spec.callTarget) {
					tc.add(rva, fact.text, fact.possible, "call")
				}
			}
			if inst.Op == x86asm.JMP && isTailCall(inst, st, bin, rva, fn) {
				for _, fact := range callArgumentFacts(inst, st, bin, rva, spec.immediate, "tail-call", spec.callTarget) {
					tc.add(rva, fact.text, fact.possible, "call")
				}
			}
			writtenFamily, writtenWidth, beforeWritten, wrote := executeAbstractInstruction(&st, inst, bin, bin.imageBase+uint64(rva))
			if wrote {
				now := readFamilyWidth(st, writtenFamily, writtenWidth)
				if now.contains(spec.immediate) && !beforeWritten.contains(spec.immediate) {
					text := fmt.Sprintf("%s produced %s=0x%x", x86asm.IntelSyntax(inst, bin.imageBase+uint64(rva), nil),
						gprDisplayName(writtenFamily, writtenWidth), spec.immediate)
					tc.add(rva, text, now.possible(spec.immediate), "producer")
				}
			}
			succ := flowSuccessors(sec.data, inst, pos)
			if sw, ok := switches[pos]; ok {
				succ = sw
			}
			if len(succ) == 1 && succ[0] == pos+inst.Len && !leaders[succ[0]] {
				pos = succ[0] // straight-line: same block
				continue
			}
			return st, succ
		}
	}
	tc.finalPass = false
	queued := map[int]bool{start: true}
	queue := []int{start}
	for len(queue) > 0 {
		leader := queue[0]
		queue = queue[1:]
		queued[leader] = false
		st, succ := runBlock(leader)
		for _, successor := range succ {
			if _, ok := insts[successor]; !ok {
				continue
			}
			old, exists := states[successor]
			changed := false
			if !exists {
				states[successor] = st.clone()
				changed = true
			} else if changed = mergeAbstractState(&old, st); changed {
				states[successor] = old
			}
			if changed && !queued[successor] {
				queue = append(queue, successor)
				queued[successor] = true
			}
		}
	}
	tc.finalPass = true
	leadersSorted := make([]int, 0, len(states))
	for l := range states {
		leadersSorted = append(leadersSorted, l)
	}
	sort.Ints(leadersSorted)
	for _, l := range leadersSorted {
		runBlock(l)
	}
}

// flowSuccessors are the in-function successors of inst at pos: none after a
// return or int3, the target of a direct jmp, else the fall-through and any
// direct branch target.
func flowSuccessors(data []byte, inst x86asm.Inst, pos int) []int {
	if data[pos] == 0xCC {
		return nil
	}
	switch inst.Op {
	case x86asm.RET, x86asm.LRET, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ:
		return nil
	case x86asm.JMP:
		if target, ok := branchTargetOff(inst, pos); ok {
			return []int{target}
		}
		return nil
	}
	next := pos + inst.Len
	if target, ok := branchTargetOff(inst, pos); ok {
		return []int{target, next}
	}
	return []int{next}
}

// functionBlocks decodes the instructions reachable from start within the
// body ranges -- other known function starts are walls -- and marks the
// basic-block leaders (the start and every instruction with a predecessor
// other than the one before it). It spends budget per decoded instruction.
func functionBlocks(data []byte, start int, ranges [][2]int, mode int, secRVA uint32, starts map[uint32]bool, budget *atomic.Int64,
	cases func(int, x86asm.Inst) []int) (map[int]x86asm.Inst, map[int]bool, map[int][]int) {
	rangeEnd := func(pos int) int {
		for _, r := range ranges {
			if pos >= r[0] && pos < r[1] {
				return r[1]
			}
		}
		return -1
	}
	insts := map[int]x86asm.Inst{}
	leaders := map[int]bool{start: true}
	switches := map[int][]int{} // switch jump -> its case blocks
	stack := []int{start}
	for len(stack) > 0 && budget.Load() > 0 {
		pos := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		end := rangeEnd(pos)
		if end < 0 {
			continue
		}
		if _, seen := insts[pos]; seen || (pos != start && starts[secRVA+uint32(pos)]) {
			continue
		}
		inst, err := x86asm.Decode(data[pos:], mode)
		if err != nil || inst.Len <= 0 || pos+inst.Len > end {
			continue
		}
		budget.Add(-1)
		insts[pos] = inst
		succ := flowSuccessors(data, inst, pos)
		if inst.Op == x86asm.JMP && len(succ) == 0 && cases != nil {
			if cs := cases(pos, inst); len(cs) > 0 {
				switches[pos] = cs
				succ = cs
			}
		}
		for _, t := range succ {
			if t != pos+inst.Len || len(succ) > 1 {
				leaders[t] = true
			}
		}
		stack = append(stack, succ...)
	}
	return insts, leaders, switches
}

func analyzeInstructionReachability(bin *cgBinary) (*rvaBits, *rvaBits, bool) {
	reachable, interiors, _, complete := analyzeInstructionFlows(bin, instructionSearchSpec{}, false, 0)
	return reachable, interiors, complete
}

func sectionContainingRVA(sections []cgSection, rva uint32) *cgSection {
	for i := range sections {
		if uint64(rva) >= uint64(sections[i].rva) && uint64(rva) < uint64(sections[i].rva)+uint64(len(sections[i].data)) {
			return &sections[i]
		}
	}
	return nil
}

type callArgFact struct {
	text     string
	possible bool
}

func callArgumentFacts(inst x86asm.Inst, state abstractState, bin *cgBinary, rva uint32, target uint64, callKind, targetFilter string) []callArgFact {
	callTarget := describeCallTarget(inst, state, bin, rva)
	if targetFilter != "" && !strings.Contains(strings.ToLower(callTarget), targetFilter) {
		return nil
	}
	var facts []callArgFact
	if bin.is64 {
		families := []int{1, 2, 8, 9} // Windows x64: RCX, RDX, R8, R9
		if bin.format != "PE" {
			families = []int{7, 6, 2, 1, 8, 9} // SysV x64: RDI, RSI, RDX, RCX, R8, R9
		}
		for i, family := range families {
			v := state.regs[family]
			if v.contains(target) {
				facts = append(facts, callArgFact{
					text:     fmt.Sprintf("%s %s with arg%d %s/%s=0x%x", callKind, callTarget, i+1, gprDisplayName(family, 64), gprDisplayName(family, 32), target),
					possible: v.possible(target),
				})
			}
		}
		sp := state.regs[4]
		if sp.kind == 2 {
			stackBase := int64(0x20)
			firstStackArg := len(families) + 1
			if bin.format != "PE" {
				stackBase = 0
			}
			for i := 0; i < 8; i++ {
				if v, ok := state.stack[sp.stack+stackBase+int64(i*8)]; ok && v.contains(target) {
					facts = append(facts, callArgFact{
						text:     fmt.Sprintf("%s %s with stack arg%d=0x%x", callKind, callTarget, i+firstStackArg, target),
						possible: v.possible(target),
					})
				}
			}
		}
	} else {
		sp := state.regs[4]
		if sp.kind == 2 {
			for i := 0; i < 12; i++ {
				if v, ok := state.stack[sp.stack+int64(i*4)]; ok && v.contains(target) {
					facts = append(facts, callArgFact{
						text:     fmt.Sprintf("%s %s with stack arg%d=0x%x", callKind, callTarget, i+1, target),
						possible: v.possible(target),
					})
				}
			}
		}
	}
	return facts
}

func isTailCall(inst x86asm.Inst, state abstractState, bin *cgBinary, rva uint32, fn funcRange) bool {
	if inst.Op != x86asm.JMP || len(inst.Args) == 0 {
		return false
	}
	switch arg := inst.Args[0].(type) {
	case x86asm.Rel:
		target := int64(rva) + int64(inst.Len) + int64(arg)
		return target < int64(fn.begin) || target >= int64(fn.end)
	case x86asm.Reg:
		value := readRegister(state, arg)
		return value.kind == 1 && len(value.consts) == 1
	case x86asm.Mem:
		if bin.is64 && arg.Base == x86asm.RIP {
			va := bin.imageBase + uint64(rva) + uint64(inst.Len) + uint64(memDisp(arg))
			_, known := bin.symbols[va]
			return known
		}
	}
	return false
}

func describeCallTarget(inst x86asm.Inst, state abstractState, bin *cgBinary, rva uint32) string {
	if len(inst.Args) > 0 {
		switch arg := inst.Args[0].(type) {
		case x86asm.Rel:
			va := bin.imageBase + uint64(rva) + uint64(inst.Len) + uint64(int64(arg))
			if name, ok := bin.symbols[va]; ok {
				return fmt.Sprintf("0x%x %s", va, name)
			}
			return fmt.Sprintf("0x%x", va)
		case x86asm.Mem:
			if bin.is64 && arg.Base == x86asm.RIP {
				va := bin.imageBase + uint64(rva) + uint64(inst.Len) + uint64(memDisp(arg))
				if name, ok := bin.symbols[va]; ok {
					return fmt.Sprintf("[0x%x] %s", va, name)
				}
				return fmt.Sprintf("[0x%x]", va)
			}
			if !bin.is64 && arg.Base == 0 && arg.Index == 0 { // x86 call [IAT slot]
				va := uint64(uint32(arg.Disp))
				if ref, ok := bin.imports[va]; ok {
					return fmt.Sprintf("[0x%x] %s!%s", va, strings.TrimSuffix(strings.ToLower(ref.dll), ".dll"), ref.display())
				}
				if name, ok := bin.symbols[va]; ok {
					return fmt.Sprintf("[0x%x] %s", va, name)
				}
				return fmt.Sprintf("[0x%x]", va)
			}
		case x86asm.Reg:
			value := readRegister(state, arg)
			if value.kind == 1 && len(value.consts) == 1 {
				va := value.consts[0]
				if name, ok := bin.symbols[va]; ok {
					return fmt.Sprintf("0x%x %s (via %s)", va, name, gprDisplayNameFromReg(arg))
				}
				return fmt.Sprintf("0x%x (via %s)", va, gprDisplayNameFromReg(arg))
			}
		}
	}
	return x86asm.IntelSyntax(inst, bin.imageBase+uint64(rva), nil)
}

// executeAbstractInstruction updates the bounded register/stack state. It
// returns the explicit destination register (when any), its value before the
// instruction, and whether the instruction wrote it.
func executeAbstractInstruction(state *abstractState, inst x86asm.Inst, bin *cgBinary, va uint64) (int, int, abstractValue, bool) {
	is64 := bin.is64
	op := strings.ToUpper(inst.Op.String())
	ptrWidth := 32
	if is64 {
		ptrWidth = 64
	}

	var dstReg x86asm.Reg
	if len(inst.Args) > 0 {
		dstReg, _ = inst.Args[0].(x86asm.Reg)
	}
	family, width, _, hasDst := gprDescriptor(dstReg)
	before := unknownValue()
	if hasDst {
		before = readRegister(*state, dstReg)
	}
	writeDst := func(v abstractValue) (int, int, abstractValue, bool) {
		if !hasDst {
			return 0, 0, unknownValue(), false
		}
		writeRegister(state, dstReg, v)
		return family, width, before, true
	}
	if strings.HasPrefix(op, "CMOV") && len(inst.Args) >= 2 && hasDst {
		selected := readOperandWithStatic(*state, inst.Args[1], is64, va, inst.Len, width, bin)
		return writeDst(mergeAbstractValue(before, selected))
	}

	switch op {
	case "MOV":
		if len(inst.Args) < 2 {
			break
		}
		value := readOperandWithStatic(*state, inst.Args[1], is64, va, inst.Len, width, bin)
		if hasDst {
			return writeDst(value)
		}
		if mem, ok := inst.Args[0].(x86asm.Mem); ok {
			if key, ok := stackMemoryKey(*state, mem, va, inst.Len); ok {
				if value.kind == 0 {
					delete(state.stack, key)
				} else {
					state.stack[key] = value.clone()
				}
			}
		}
		return 0, 0, unknownValue(), false
	case "MOVZX":
		if len(inst.Args) >= 2 && hasDst {
			srcWidth := operandWidth(inst.Args[1], inst.MemBytes*8)
			return writeDst(readOperandWithStatic(*state, inst.Args[1], is64, va, inst.Len, srcWidth, bin))
		}
	case "MOVSX", "MOVSXD":
		if len(inst.Args) >= 2 && hasDst {
			srcWidth := operandWidth(inst.Args[1], inst.MemBytes*8)
			v := readOperandWithStatic(*state, inst.Args[1], is64, va, inst.Len, srcWidth, bin)
			return writeDst(mapConstants(v, func(x uint64) uint64 { return signExtend(x, srcWidth) }))
		}
	case "LEA":
		if len(inst.Args) >= 2 && hasDst {
			if mem, ok := inst.Args[1].(x86asm.Mem); ok {
				return writeDst(effectiveAddress(*state, mem, va, inst.Len))
			}
		}
	case "ADD", "SUB", "AND", "OR", "XOR", "SHL", "SAL", "SHR", "SAR":
		if len(inst.Args) >= 2 && hasDst {
			left := readRegister(*state, dstReg)
			right := readOperandWithStatic(*state, inst.Args[1], is64, va, inst.Len, width, bin)
			if op == "XOR" {
				if src, ok := inst.Args[1].(x86asm.Reg); ok && src == dstReg {
					return writeDst(constantValue(0))
				}
			}
			return writeDst(binaryAbstract(op, left, right, width))
		}
	case "IMUL":
		if hasDst {
			if len(inst.Args) >= 3 {
				return writeDst(binaryAbstract("IMUL", readOperandWithStatic(*state, inst.Args[1], is64, va, inst.Len, width, bin),
					readOperandWithStatic(*state, inst.Args[2], is64, va, inst.Len, width, bin), width))
			}
			if len(inst.Args) >= 2 {
				return writeDst(binaryAbstract("IMUL", before, readOperandWithStatic(*state, inst.Args[1], is64, va, inst.Len, width, bin), width))
			}
		}
	case "INC", "DEC":
		if hasDst {
			delta := constantValue(1)
			if op == "DEC" {
				return writeDst(binaryAbstract("SUB", before, delta, width))
			}
			return writeDst(binaryAbstract("ADD", before, delta, width))
		}
	case "NEG", "NOT":
		if hasDst {
			return writeDst(mapConstants(before, func(x uint64) uint64 {
				if op == "NEG" {
					return maskWidth(^x+1, width)
				}
				return maskWidth(^x, width)
			}))
		}
	case "PUSH":
		if len(inst.Args) > 0 {
			value := readOperand(*state, inst.Args[0], is64, va, inst.Len)
			sp := state.regs[4]
			if sp.kind == 2 {
				bytes := int64(ptrWidth / 8)
				sp.stack -= bytes
				state.regs[4] = sp
				state.stack[sp.stack] = value
			} else {
				state.regs[4] = unknownValue()
			}
		}
		return 0, 0, unknownValue(), false
	case "POP":
		if hasDst {
			sp := state.regs[4]
			value := unknownValue()
			if sp.kind == 2 {
				value = state.stack[sp.stack]
				delete(state.stack, sp.stack)
				sp.stack += int64(ptrWidth / 8)
				state.regs[4] = sp
			}
			return writeDst(value)
		}
	case "CALL", "LCALL":
		clobberCallRegisters(state, bin)
		// A 32-bit callee that ends in ret N pops its own arguments (stdcall,
		// thiscall): without this the stack pointer drifts by N per call and
		// a loop around the call widens it to unknown at the loop head.
		if n := calleePurge(bin, inst, va); n > 0 && state.regs[4].kind == 2 {
			sp := state.regs[4]
			for off := sp.stack; off < sp.stack+int64(n); off++ {
				delete(state.stack, off)
			}
			sp.stack += int64(n)
			state.regs[4] = sp
		}
		return 0, 0, unknownValue(), false
	case "XCHG":
		if len(inst.Args) >= 2 && hasDst {
			other, ok := inst.Args[1].(x86asm.Reg)
			if ok {
				left, right := before, readRegister(*state, other)
				writeRegister(state, dstReg, right)
				writeRegister(state, other, left)
				return family, width, before, true
			}
		}
	}

	// Conservatively forget explicit destinations for operations not modelled.
	// Losing a fact is preferable to carrying a stale constant across a write.
	if hasDst && instructionUsuallyWritesFirst(op) {
		writeRegister(state, dstReg, unknownValue())
		return family, width, before, true
	}
	if op == "MUL" || op == "DIV" || op == "IDIV" {
		state.regs[0], state.regs[2] = unknownValue(), unknownValue()
	}
	return 0, 0, unknownValue(), false
}

func instructionUsuallyWritesFirst(op string) bool {
	if op == "CMP" || op == "TEST" || op == "PUSH" || op == "CALL" || op == "LCALL" ||
		op == "JMP" || op == "NOP" || strings.HasPrefix(op, "J") || strings.HasPrefix(op, "LOOP") ||
		strings.HasPrefix(op, "RET") || op == "BT" {
		return false
	}
	return true
}

// calleePurge is the byte count a 32-bit callee pops on return (the N of its
// ret N): for a direct call, found by walking the callee's control flow --
// a thunk that jumps through the import table takes the import's size --
// and for call [IAT slot], read from the imported DLL (importPurge). 0 when
// the callee returns with a plain ret or cannot be resolved.
func calleePurge(bin *cgBinary, inst x86asm.Inst, va uint64) int {
	if bin.is64 || len(inst.Args) == 0 {
		return 0
	}
	switch a := inst.Args[0].(type) {
	case x86asm.Mem:
		if a.Base == 0 && a.Index == 0 {
			return bin.slotPurge(uint64(uint32(a.Disp)))
		}
		return 0
	case x86asm.Rel:
		target := uint32(int64(va-bin.imageBase) + int64(inst.Len) + int64(a))
		bin.purgeMu.Lock()
		n, ok := bin.purge[target]
		bin.purgeMu.Unlock()
		if ok {
			return n
		}
		n = bin.walkPurge(target)
		bin.purgeMu.Lock()
		if bin.purge == nil {
			bin.purge = map[uint32]int{}
		}
		bin.purge[target] = n
		bin.purgeMu.Unlock()
		return n
	}
	return 0
}

// walkPurge follows a local function's control flow to its ret N.
func (bin *cgBinary) walkPurge(target uint32) int {
	sec := sectionContainingRVA(bin.execSections, target)
	if sec == nil {
		return 0
	}
	seen := map[int]bool{}
	stack := []int{int(target - sec.rva)}
	for len(stack) > 0 && len(seen) < 4000 {
		pos := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if pos < 0 || pos >= len(sec.data) || seen[pos] {
			continue
		}
		seen[pos] = true
		in, err := x86asm.Decode(sec.data[pos:], 32)
		if err != nil || in.Len == 0 || sec.data[pos] == 0xCC {
			continue
		}
		if in.Op == x86asm.RET {
			if imm, ok := in.Args[0].(x86asm.Imm); ok {
				return int(imm)
			}
			return 0
		}
		if in.Op == x86asm.JMP {
			if m, ok := in.Args[0].(x86asm.Mem); ok && m.Base == 0 && m.Index == 0 {
				return bin.slotPurge(uint64(uint32(m.Disp)))
			}
		}
		stack = append(stack, flowSuccessors(sec.data, in, pos)...)
	}
	return 0
}

// slotPurge is the argument size of the function imported into an IAT slot.
func (bin *cgBinary) slotPurge(slot uint64) int {
	ref, ok := bin.imports[slot]
	if !ok {
		return 0
	}
	return importPurge(bin.path, ref)
}

func clobberCallRegisters(state *abstractState, bin *cgBinary) {
	if bin.is64 {
		families := []int{0, 1, 2, 8, 9, 10, 11} // Windows x64 volatile GPRs
		if bin.format != "PE" {
			families = []int{0, 1, 2, 6, 7, 8, 9, 10, 11} // SysV x64 caller-saved GPRs
		}
		for _, family := range families {
			state.regs[family] = unknownValue()
		}
	} else {
		for _, family := range []int{0, 1, 2} {
			state.regs[family] = unknownValue()
		}
	}
}

func readOperand(state abstractState, arg x86asm.Arg, is64 bool, va uint64, instLen int) abstractValue {
	switch value := arg.(type) {
	case x86asm.Reg:
		return readRegister(state, value)
	case x86asm.Imm:
		return constantValue(uint64(int64(value)))
	case x86asm.Mem:
		if key, ok := stackMemoryKey(state, value, va, instLen); ok {
			return state.stack[key].clone()
		}
	}
	return unknownValue()
}

func readOperandWithStatic(state abstractState, arg x86asm.Arg, is64 bool, va uint64, instLen, width int, bin *cgBinary) abstractValue {
	value := readOperand(state, arg, is64, va, instLen)
	if value.kind != 0 {
		return value
	}
	mem, ok := arg.(x86asm.Mem)
	if !ok {
		return value
	}
	address := effectiveAddress(state, mem, va, instLen)
	if address.kind != 1 || len(address.consts) != 1 {
		return value
	}
	if loaded, ok := readStaticConstant(bin, address.consts[0], width); ok {
		return constantValue(loaded)
	}
	return value
}

func readStaticConstant(bin *cgBinary, va uint64, width int) (uint64, bool) {
	if width != 8 && width != 16 && width != 32 && width != 64 {
		return 0, false
	}
	if va < bin.imageBase || va-bin.imageBase > 0xFFFFFFFF {
		return 0, false
	}
	rva := uint32(va - bin.imageBase)
	byteCount := width / 8
	for _, sec := range bin.staticSections {
		if rva < sec.rva {
			continue
		}
		off := uint64(rva - sec.rva)
		if off+uint64(byteCount) > uint64(len(sec.data)) {
			continue
		}
		data := sec.data[off : off+uint64(byteCount)]
		switch width {
		case 8:
			return uint64(data[0]), true
		case 16:
			return uint64(binary.LittleEndian.Uint16(data)), true
		case 32:
			return uint64(binary.LittleEndian.Uint32(data)), true
		case 64:
			return binary.LittleEndian.Uint64(data), true
		}
	}
	return 0, false
}

func effectiveAddress(state abstractState, mem x86asm.Mem, va uint64, instLen int) abstractValue {
	if mem.Base == x86asm.RIP {
		return constantValue(va + uint64(instLen) + uint64(memDisp(mem)))
	}
	base := constantValue(0)
	if mem.Base != 0 {
		base = readRegister(state, mem.Base)
	}
	index := constantValue(0)
	if mem.Index != 0 {
		index = readRegister(state, mem.Index)
		index = mapConstants(index, func(x uint64) uint64 { return x * uint64(mem.Scale) })
	}
	result := binaryAbstract("ADD", base, index, 64)
	return addSignedConstant(result, memDisp(mem))
}

func stackMemoryKey(state abstractState, mem x86asm.Mem, va uint64, instLen int) (int64, bool) {
	addr := effectiveAddress(state, mem, va, instLen)
	if addr.kind != 2 {
		return 0, false
	}
	return addr.stack, true
}

func addSignedConstant(value abstractValue, delta int64) abstractValue {
	if value.kind == 2 {
		value.stack += delta
		return value
	}
	if value.kind == 1 {
		return mapConstants(value, func(x uint64) uint64 { return x + uint64(delta) })
	}
	return unknownValue()
}

func binaryAbstract(op string, left, right abstractValue, width int) abstractValue {
	if (op == "ADD" || op == "SUB") && left.kind == 2 && right.kind == 1 && len(right.consts) == 1 {
		delta := int64(right.consts[0])
		if op == "SUB" {
			delta = -delta
		}
		return stackValue(left.stack + delta)
	}
	if left.kind != 1 || right.kind != 1 {
		return unknownValue()
	}
	set := make(map[uint64]bool)
	for _, a := range left.consts {
		for _, b := range right.consts {
			var result uint64
			switch op {
			case "ADD":
				result = a + b
			case "SUB":
				result = a - b
			case "AND":
				result = a & b
			case "OR":
				result = a | b
			case "XOR":
				result = a ^ b
			case "SHL", "SAL":
				result = a << (b & 63)
			case "SHR":
				result = a >> (b & 63)
			case "SAR":
				result = uint64(int64(signExtend(a, width)) >> (b & 63))
			case "IMUL":
				result = a * b
			default:
				return unknownValue()
			}
			set[maskWidth(result, width)] = true
			if len(set) > maxAbstractConstants {
				return unknownValue()
			}
		}
	}
	vals := make([]uint64, 0, len(set))
	for value := range set {
		vals = append(vals, value)
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	return abstractValue{kind: 1, consts: vals}
}

func mapConstants(value abstractValue, fn func(uint64) uint64) abstractValue {
	if value.kind != 1 {
		return unknownValue()
	}
	set := make(map[uint64]bool)
	for _, old := range value.consts {
		set[fn(old)] = true
	}
	vals := make([]uint64, 0, len(set))
	for v := range set {
		vals = append(vals, v)
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	return abstractValue{kind: 1, consts: vals}
}

func readRegister(state abstractState, reg x86asm.Reg) abstractValue {
	family, width, shift, ok := gprDescriptor(reg)
	if !ok {
		return unknownValue()
	}
	return narrowAbstractValue(state.regs[family], width, shift)
}

func readFamilyWidth(state abstractState, family, width int) abstractValue {
	return narrowAbstractValue(state.regs[family], width, 0)
}

func narrowAbstractValue(value abstractValue, width int, shift uint) abstractValue {
	if value.kind == 2 {
		if width == 64 && shift == 0 {
			return value
		}
		return unknownValue()
	}
	if value.kind != 1 {
		return unknownValue()
	}
	return mapConstants(value, func(x uint64) uint64 { return maskWidth(x>>shift, width) })
}

func writeRegister(state *abstractState, reg x86asm.Reg, value abstractValue) {
	family, width, shift, ok := gprDescriptor(reg)
	if !ok {
		return
	}
	if width == 64 || width == 32 {
		if value.kind == 1 {
			value = mapConstants(value, func(x uint64) uint64 { return maskWidth(x, width) })
		} else if value.kind == 2 && width != 64 {
			value = unknownValue()
		}
		state.regs[family] = value
		return
	}
	old := state.regs[family]
	if old.kind != 1 || value.kind != 1 {
		state.regs[family] = unknownValue()
		return
	}
	mask := maskWidth(^uint64(0), width) << shift
	set := make(map[uint64]bool)
	for _, a := range old.consts {
		for _, b := range value.consts {
			set[(a&^mask)|((b<<shift)&mask)] = true
			if len(set) > maxAbstractConstants {
				state.regs[family] = unknownValue()
				return
			}
		}
	}
	vals := make([]uint64, 0, len(set))
	for v := range set {
		vals = append(vals, v)
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	state.regs[family] = abstractValue{kind: 1, consts: vals}
}

func maskWidth(value uint64, width int) uint64 {
	if width <= 0 || width >= 64 {
		return value
	}
	return value & (uint64(1)<<uint(width) - 1)
}

func signExtend(value uint64, width int) uint64 {
	if width <= 0 || width >= 64 {
		return value
	}
	shift := uint(64 - width)
	return uint64(int64(value<<shift) >> shift)
}

func operandWidth(arg x86asm.Arg, fallback int) int {
	if reg, ok := arg.(x86asm.Reg); ok {
		_, width, _, valid := gprDescriptor(reg)
		if valid {
			return width
		}
	}
	if fallback == 8 || fallback == 16 || fallback == 32 || fallback == 64 {
		return fallback
	}
	return 64
}

func gprDescriptor(reg x86asm.Reg) (family int, width int, shift uint, ok bool) {
	groups := [][]x86asm.Reg{
		{x86asm.AL, x86asm.AX, x86asm.EAX, x86asm.RAX},
		{x86asm.CL, x86asm.CX, x86asm.ECX, x86asm.RCX},
		{x86asm.DL, x86asm.DX, x86asm.EDX, x86asm.RDX},
		{x86asm.BL, x86asm.BX, x86asm.EBX, x86asm.RBX},
		{x86asm.SPB, x86asm.SP, x86asm.ESP, x86asm.RSP},
		{x86asm.BPB, x86asm.BP, x86asm.EBP, x86asm.RBP},
		{x86asm.SIB, x86asm.SI, x86asm.ESI, x86asm.RSI},
		{x86asm.DIB, x86asm.DI, x86asm.EDI, x86asm.RDI},
		{x86asm.R8B, x86asm.R8W, x86asm.R8L, x86asm.R8},
		{x86asm.R9B, x86asm.R9W, x86asm.R9L, x86asm.R9},
		{x86asm.R10B, x86asm.R10W, x86asm.R10L, x86asm.R10},
		{x86asm.R11B, x86asm.R11W, x86asm.R11L, x86asm.R11},
		{x86asm.R12B, x86asm.R12W, x86asm.R12L, x86asm.R12},
		{x86asm.R13B, x86asm.R13W, x86asm.R13L, x86asm.R13},
		{x86asm.R14B, x86asm.R14W, x86asm.R14L, x86asm.R14},
		{x86asm.R15B, x86asm.R15W, x86asm.R15L, x86asm.R15},
	}
	for f, regs := range groups {
		for i, candidate := range regs {
			if reg == candidate {
				return f, []int{8, 16, 32, 64}[i], 0, true
			}
		}
	}
	switch reg {
	case x86asm.AH:
		return 0, 8, 8, true
	case x86asm.CH:
		return 1, 8, 8, true
	case x86asm.DH:
		return 2, 8, 8, true
	case x86asm.BH:
		return 3, 8, 8, true
	}
	return 0, 0, 0, false
}

func parseGPRName(raw string) (family, width int, ok bool) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	aliases := map[string]string{
		"SPL": "SPB", "BPL": "BPB", "SIL": "SIB", "DIL": "DIB",
		"R8D": "R8L", "R9D": "R9L", "R10D": "R10L", "R11D": "R11L",
		"R12D": "R12L", "R13D": "R13L", "R14D": "R14L", "R15D": "R15L",
	}
	if alias, exists := aliases[s]; exists {
		s = alias
	}
	for reg := x86asm.AL; reg <= x86asm.R15; reg++ {
		if reg.String() == s {
			family, width, _, ok = gprDescriptor(reg)
			return
		}
	}
	return 0, 0, false
}

func gprDisplayName(family, width int) string {
	names64 := []string{"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	names32 := []string{"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D"}
	names16 := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8W", "R9W", "R10W", "R11W", "R12W", "R13W", "R14W", "R15W"}
	names8 := []string{"AL", "CL", "DL", "BL", "SPL", "BPL", "SIL", "DIL", "R8B", "R9B", "R10B", "R11B", "R12B", "R13B", "R14B", "R15B"}
	if family < 0 || family >= 16 {
		return "?"
	}
	switch width {
	case 8:
		return names8[family]
	case 16:
		return names16[family]
	case 32:
		return names32[family]
	default:
		return names64[family]
	}
}

func gprDisplayNameFromReg(reg x86asm.Reg) string {
	family, width, _, ok := gprDescriptor(reg)
	if !ok {
		return reg.String()
	}
	return gprDisplayName(family, width)
}
