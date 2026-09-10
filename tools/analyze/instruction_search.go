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
	"sort"
	"strconv"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

const (
	defaultInstructionSearchResults = 200
	maxInstructionSearchResults     = 1000
	instructionSearchBudget         = 8_000_000
	maxAbstractConstants            = 8
)

type instructionSearchSpec struct {
	mnemonic     string
	regFamily    int
	regWidth     int
	hasRegister  bool
	immediate    uint64
	hasImmediate bool
	callTarget   string
	findings     string
}

type instructionHit struct {
	rva        uint32
	text       string
	confidence string
	function   uint32
	hasFunc    bool
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
			fn := ""
			if hit.hasFunc {
				fn = fmt.Sprintf(" function=0x%x", bin.imageBase+uint64(hit.function))
			}
			sb.WriteString(fmt.Sprintf("  [%s] VA 0x%x RVA 0x%x%s: %s\n", hit.confidence, va, hit.rva, fn, hit.text))
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
				sb.WriteString(fmt.Sprintf("  [%s] VA 0x%x RVA 0x%x: %s\n", confidence,
					bin.imageBase+uint64(hit.rva), hit.rva, hit.text))
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
	if spec.mnemonic == "" && !spec.hasRegister && !spec.hasImmediate {
		return spec, fmt.Errorf("instruction_search requires at least one of mnemonic, register, or immediate")
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
	if spec.callTarget != "" {
		parts = append(parts, "call_target="+spec.callTarget)
	}
	if spec.findings != "all" {
		parts = append(parts, "findings="+spec.findings)
	}
	return strings.Join(parts, ", ")
}

func exhaustiveInstructionMatches(bin *cgBinary, spec instructionSearchSpec, reachable, interiors map[uint32]bool, maxResults int) ([]instructionHit, int) {
	mode := 32
	if bin.is64 {
		mode = 64
	}
	var confirmed []instructionHit
	var candidates []instructionHit
	total := 0
	for _, sec := range bin.execSections {
		for off := 0; off < len(sec.data); off++ {
			rva := sec.rva + uint32(off)
			// A byte inside a CFG-confirmed instruction cannot independently be
			// another instruction start. This removes REX-prefix false duplicates
			// and immediate bytes that happen to decode as plausible opcodes.
			if interiors[rva] {
				continue
			}
			inst, err := x86asm.Decode(sec.data[off:], mode)
			if err != nil || inst.Len <= 0 || !instructionMatches(inst, spec) {
				continue
			}
			total++
			hit := instructionHit{
				rva:        rva,
				text:       x86asm.IntelSyntax(inst, bin.imageBase+uint64(rva), nil),
				confidence: "candidate",
			}
			if reachable[rva] {
				hit.confidence = "confirmed"
			}
			if fn := findFunc(bin.funcTable, rva); fn != nil {
				hit.function, hit.hasFunc = fn.begin, true
			}
			if hit.confidence == "confirmed" {
				if len(confirmed) < maxResults {
					confirmed = append(confirmed, hit)
				}
			} else if len(candidates) < maxResults {
				candidates = append(candidates, hit)
			}
		}
	}
	sort.Slice(confirmed, func(i, j int) bool { return confirmed[i].rva < confirmed[j].rva })
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].rva < candidates[j].rva })
	hits := append([]instructionHit(nil), confirmed...)
	remaining := maxResults - len(hits)
	if remaining > len(candidates) {
		remaining = len(candidates)
	}
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

func analyzeInstructionFlows(bin *cgBinary, spec instructionSearchSpec, trace bool, maxResults int) (map[uint32]bool, map[uint32]bool, []valueTraceHit, bool) {
	if !trace {
		reachable, interiors, complete := analyzeInstructionReachability(bin)
		return reachable, interiors, nil, complete
	}
	reachable := make(map[uint32]bool)
	interiors := make(map[uint32]bool)
	var traces []valueTraceHit
	traceIndex := make(map[string]int)
	addTrace := func(rva uint32, text string, possible bool, kind string) {
		if (spec.findings == "call" && kind != "call") || (spec.findings == "producer" && kind != "producer") {
			return
		}
		key := fmt.Sprintf("%x:%s", rva, text)
		if index, exists := traceIndex[key]; exists {
			// A later CFG merge may reveal alternative values that were not
			// present on the first path processed through this instruction.
			traces[index].possible = traces[index].possible || possible
			return
		}
		if len(traces) >= maxResults {
			return
		}
		traceIndex[key] = len(traces)
		traces = append(traces, valueTraceHit{rva: rva, text: text, possible: possible, kind: kind})
	}
	starts := make(map[uint32]bool, len(bin.funcTable))
	for _, fn := range bin.funcTable {
		starts[fn.begin] = true
	}
	budget := instructionSearchBudget

	for _, fn := range bin.funcTable {
		if budget <= 0 {
			break
		}
		sec := sectionContainingRVA(bin.execSections, fn.begin)
		if sec == nil {
			continue
		}
		mode := 32
		if bin.is64 {
			mode = 64
		}
		start := int(fn.begin - sec.rva)
		end := int(fn.end - sec.rva)
		if end > len(sec.data) {
			end = len(sec.data)
		}
		if start < 0 || start >= end {
			continue
		}

		states := map[int]abstractState{start: newAbstractState(bin.is64)}
		queued := map[int]bool{start: true}
		queue := []int{start}
		for len(queue) > 0 && budget > 0 {
			pos := queue[0]
			queue = queue[1:]
			queued[pos] = false
			if pos < start || pos >= end {
				continue
			}
			rva := sec.rva + uint32(pos)
			if pos != start && starts[rva] {
				continue
			}
			inst, err := x86asm.Decode(sec.data[pos:], mode)
			if err != nil || inst.Len <= 0 || pos+inst.Len > end {
				continue
			}
			budget--
			reachable[rva] = true
			for byteOff := 1; byteOff < inst.Len; byteOff++ {
				interiors[rva+uint32(byteOff)] = true
			}
			before := states[pos]
			after := before.clone()

			if trace && spec.hasImmediate && (inst.Op == x86asm.CALL || inst.Op == x86asm.LCALL) {
				for _, fact := range callArgumentFacts(inst, before, bin, rva, spec.immediate, "call", spec.callTarget) {
					addTrace(rva, fact.text, fact.possible, "call")
				}
			}
			if trace && spec.hasImmediate && inst.Op == x86asm.JMP && isTailCall(inst, before, bin, rva, fn) {
				for _, fact := range callArgumentFacts(inst, before, bin, rva, spec.immediate, "tail-call", spec.callTarget) {
					addTrace(rva, fact.text, fact.possible, "call")
				}
			}

			writtenFamily, writtenWidth, beforeWritten, wrote := executeAbstractInstruction(&after, inst, bin, bin.imageBase+uint64(rva))
			if trace && spec.hasImmediate && wrote {
				now := readFamilyWidth(after, writtenFamily, writtenWidth)
				if now.contains(spec.immediate) && !beforeWritten.contains(spec.immediate) {
					text := fmt.Sprintf("%s produced %s=0x%x", x86asm.IntelSyntax(inst, bin.imageBase+uint64(rva), nil),
						gprDisplayName(writtenFamily, writtenWidth), spec.immediate)
					addTrace(rva, text, now.possible(spec.immediate), "producer")
				}
			}

			next := pos + inst.Len
			var successors []int
			if sec.data[pos] != 0xCC {
				switch inst.Op {
				case x86asm.RET, x86asm.LRET, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ:
				case x86asm.JMP:
					if target, ok := branchTargetOff(inst, pos); ok {
						successors = append(successors, target)
					}
				default:
					if target, ok := branchTargetOff(inst, pos); ok {
						successors = append(successors, target)
					}
					successors = append(successors, next)
				}
			}
			for _, successor := range successors {
				if successor < start || successor >= end {
					continue
				}
				succRVA := sec.rva + uint32(successor)
				if successor != start && starts[succRVA] {
					continue
				}
				old, exists := states[successor]
				changed := false
				if !exists {
					states[successor] = after.clone()
					changed = true
				} else {
					changed = mergeAbstractState(&old, after)
					if changed {
						states[successor] = old
					}
				}
				if changed && !queued[successor] {
					queue = append(queue, successor)
					queued[successor] = true
				}
			}
		}
	}
	sort.Slice(traces, func(i, j int) bool {
		if traces[i].rva == traces[j].rva {
			return traces[i].text < traces[j].text
		}
		return traces[i].rva < traces[j].rva
	})
	return reachable, interiors, traces, budget > 0
}

func analyzeInstructionReachability(bin *cgBinary) (map[uint32]bool, map[uint32]bool, bool) {
	reachable := make(map[uint32]bool)
	interiors := make(map[uint32]bool)
	starts := make(map[uint32]bool, len(bin.funcTable))
	for _, fn := range bin.funcTable {
		starts[fn.begin] = true
	}
	budget := instructionSearchBudget
	mode := 32
	if bin.is64 {
		mode = 64
	}
	for _, fn := range bin.funcTable {
		if budget <= 0 {
			break
		}
		sec := sectionContainingRVA(bin.execSections, fn.begin)
		if sec == nil {
			continue
		}
		start := int(fn.begin - sec.rva)
		end := int(fn.end - sec.rva)
		if end > len(sec.data) {
			end = len(sec.data)
		}
		visited := make(map[int]bool)
		stack := []int{start}
		for len(stack) > 0 && budget > 0 {
			pos := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if pos < start || pos >= end || visited[pos] {
				continue
			}
			rva := sec.rva + uint32(pos)
			if pos != start && starts[rva] {
				continue
			}
			inst, err := x86asm.Decode(sec.data[pos:], mode)
			if err != nil || inst.Len <= 0 || pos+inst.Len > end {
				continue
			}
			visited[pos] = true
			budget--
			reachable[rva] = true
			for byteOff := 1; byteOff < inst.Len; byteOff++ {
				interiors[rva+uint32(byteOff)] = true
			}
			if sec.data[pos] == 0xCC {
				continue
			}
			next := pos + inst.Len
			switch inst.Op {
			case x86asm.RET, x86asm.LRET, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ:
			case x86asm.JMP:
				if target, ok := branchTargetOff(inst, pos); ok {
					stack = append(stack, target)
				}
			default:
				if target, ok := branchTargetOff(inst, pos); ok {
					stack = append(stack, target)
				}
				stack = append(stack, next)
			}
		}
	}
	return reachable, interiors, budget > 0
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
			va := bin.imageBase + uint64(rva) + uint64(inst.Len) + uint64(arg.Disp)
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
				va := bin.imageBase + uint64(rva) + uint64(inst.Len) + uint64(arg.Disp)
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
		return constantValue(va + uint64(instLen) + uint64(mem.Disp))
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
	return addSignedConstant(result, mem.Disp)
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
