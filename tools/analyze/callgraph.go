package analyze

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

const (
	defaultCallGraphDepth    = 2
	maxCallGraphDepth        = 5
	defaultCallGraphMaxNodes = 200
	maxCallGraphMaxNodes     = 500
)

// cgEdge represents a caller->callee relationship in the call graph.
type cgEdge struct {
	callerVA uint64
	calleeVA uint64
}

// cgSection holds preloaded executable section data for CALL scanning.
type cgSection struct {
	rva  uint32
	data []byte
}

// opCallGraph builds a static call graph rooted at a given function VA.
// x64 PE: uses .pdata for precise function boundaries.
// x86 PE: heuristic mode -- detects functions from E8 CALL targets (no .pdata needed).
func opCallGraph(input AnalyzeInput) (string, error) {
	vaStr := input.VA
	if vaStr == "" && input.TargetVA != "" {
		vaStr = input.TargetVA
	}
	if vaStr == "" {
		return "", fmt.Errorf("va is required for call_graph (the root function address)")
	}

	rootVA, err := parseHexAddr(vaStr)
	if err != nil {
		return "", fmt.Errorf("invalid va: %s", vaStr)
	}

	// Open binary: try PE, then ELF, then Mach-O
	bin, err := cgOpenBinary(input.FilePath)
	if err != nil {
		return "", err
	}
	if bin.closer != nil {
		defer bin.closer()
	}

	imageBase := bin.imageBase
	if rootVA < imageBase {
		return "", fmt.Errorf("va 0x%x is below image base 0x%x", rootVA, imageBase)
	}
	if rootVA-imageBase > 0xFFFFFFFF {
		return "", fmt.Errorf("va 0x%x is too far from image base 0x%x (RVA exceeds 4GB)", rootVA, imageBase)
	}

	is64 := bin.is64

	depth := input.Count // reuse count parameter as max_depth
	if depth <= 0 {
		depth = defaultCallGraphDepth
	}
	if depth > maxCallGraphDepth {
		depth = maxCallGraphDepth
	}

	maxNodes := input.MaxResults
	if maxNodes <= 0 {
		maxNodes = defaultCallGraphMaxNodes
	}
	if maxNodes > maxCallGraphMaxNodes {
		maxNodes = maxCallGraphMaxNodes
	}

	symbols := bin.symbols
	execSections := bin.execSections
	funcTable := bin.funcTable

	// Resolve root function
	rootRVA := uint32(rootVA - imageBase)
	rootFunc := findFunc(funcTable, rootRVA)
	if rootFunc == nil {
		if isInExecSection(execSections, rootRVA) {
			// Heuristic: root may not be a CALL/BL target (e.g. entry point,
			// indirect call target). Insert it into the table so BFS can proceed.
			funcTable = insertFunc(funcTable, rootRVA, execSections)
			rootFunc = findFunc(funcTable, rootRVA)
		}
		if rootFunc == nil {
			return "", fmt.Errorf("no function found at 0x%x. "+
				"Try function_at with va=\"0x%x\" to find the nearest function", rootVA, rootVA)
		}
	}
	if rootFunc.owner != 0 { // inside a split-off cold block: the graph is its owner's
		if owner := findFunc(funcTable, rootFunc.owner); owner != nil {
			rootFunc = owner
		}
	}

	// Known function starts (RVA) -- walls for CFG-based call scanning so a
	// function's call collection never leaks into a neighbour.
	startSet := make(map[uint32]bool, len(funcTable))
	for i := range funcTable {
		if funcTable[i].owner == 0 { // a chained fragment continues its owner
			startSet[funcTable[i].begin] = true
		}
	}

	// BFS to build call graph
	visited := make(map[uint64]int)      // VA -> depth at which visited
	imports := make(map[uint64][]string) // caller VA -> imported function names (FF 15)
	var edges []cgEdge
	type bfsItem struct {
		va    uint64
		depth int
	}
	queue := []bfsItem{{va: imageBase + uint64(rootFunc.begin), depth: 0}}
	visited[imageBase+uint64(rootFunc.begin)] = 0

	for len(queue) > 0 && len(visited) < maxNodes {
		cur := queue[0]
		queue = queue[1:]

		if cur.depth >= depth {
			continue
		}

		curRVA := uint32(cur.va - imageBase)
		curFn := findFunc(funcTable, curRVA)
		if curFn == nil {
			continue
		}

		// Scan this function's code for CALL/BL targets (arch-specific)
		var callees []cgCallTarget
		switch bin.arch {
		case "arm64":
			callees = scanCallTargetsARM64(execSections, curFn.begin, curFn.end, imageBase)
		case "arm32":
			callees = scanCallTargetsARM32(execSections, curFn.begin, curFn.end, imageBase)
		default: // x86, x64
			callees = scanCallTargetsCFG(execSections, curFn.begin, imageBase, is64, startSet)
		}

		for _, ct := range callees {
			if ct.indirect {
				// FF 15 [rip+disp32]: target is an IAT slot RVA (in .rdata, not .text).
				// Record as import call -- no BFS expansion (external function).
				iatVA := imageBase + uint64(ct.rva)
				if name, ok := symbols[iatVA]; ok {
					imports[cur.va] = append(imports[cur.va], name)
				}
				continue
			}

			// E8 rel32: filter false positives by checking executable section range.
			if !isInExecSection(execSections, ct.rva) {
				continue
			}

			calleeVA := imageBase + uint64(ct.rva)
			edges = append(edges, cgEdge{callerVA: cur.va, calleeVA: calleeVA})

			if _, seen := visited[calleeVA]; !seen && len(visited) < maxNodes {
				visited[calleeVA] = cur.depth + 1
				// Only BFS-expand if callee is a known .pdata function start.
				// Leaf functions (no .pdata entry) are shown as edges but not
				// expanded, since we can't determine their code boundaries.
				calleeFn := findFunc(funcTable, ct.rva)
				if calleeFn != nil && calleeFn.begin == ct.rva {
					queue = append(queue, bfsItem{va: calleeVA, depth: cur.depth + 1})
				}
			}
		}
	}

	// Also find callers of root (reverse direction, 1 level only)
	var rootCallers []cgCaller
	asCallers := func(rvas []uint32) []cgCaller {
		out := make([]cgCaller, len(rvas))
		for i, r := range rvas {
			out[i] = cgCaller{rva: r}
		}
		return out
	}
	switch bin.arch {
	case "arm64":
		rootCallers = asCallers(findCallersARM64(execSections, rootFunc.begin, imageBase, funcTable))
	case "arm32":
		rootCallers = asCallers(findCallersARM32(execSections, rootFunc.begin, imageBase, funcTable))
	default:
		rootCallers = findCallers(execSections, rootFunc.begin, funcTable)
	}

	// Format output
	var sb strings.Builder
	rootName := funcName(imageBase+uint64(rootFunc.begin), symbols)
	mode := ""
	if bin.arch != "x64" {
		// x86/ARM use heuristic function detection (no .pdata)
		mode = ", heuristic"
	}
	sb.WriteString(fmt.Sprintf("Call graph for %s (depth=%d, %d nodes%s):\n", rootName, depth, len(visited), mode))
	// Edges are direct CALLs collected along each function's control flow, so they
	// are high-confidence (no over-extended-boundary "fall-through" edges).
	// Indirect/computed calls can't be resolved statically and appear as imports.
	sb.WriteString("(callee edges = direct CALLs resolved via control flow; indirect calls listed as imports)\n\n")

	// Print callers
	if len(rootCallers) > 0 {
		sb.WriteString(fmt.Sprintf("Callers of %s:\n", rootName))
		for _, c := range rootCallers {
			how := ""
			switch {
			case c.thunk != 0:
				how = " (via thunk " + funcName(imageBase+uint64(c.thunk), symbols) + ")"
			case c.tail:
				how = " (tail jump)"
			}
			sb.WriteString(fmt.Sprintf("  <- %s%s\n", funcName(imageBase+uint64(c.rva), symbols), how))
		}
		sb.WriteString("\n")
	}
	// Virtual functions and callbacks have no direct callers; the data slots
	// that hold their address (vtables, handler tables) are how they are reached.
	if ptrs := rootDataRefs(input.FilePath, imageBase+uint64(rootFunc.begin), symbols); len(ptrs) > 0 {
		sb.WriteString(fmt.Sprintf("Referenced from data (indirect calls through these slots):\n%s\n", strings.Join(ptrs, "")))
	} else if len(rootCallers) == 0 {
		sb.WriteString("No direct callers and no stored pointers: reached only through computed addresses, or unused.\n\n")
	}

	// Print callees as tree
	sb.WriteString("Callees:\n")
	printCallTree(&sb, imageBase+uint64(rootFunc.begin), edges, imports, symbols, 0, depth, make(map[uint64]bool))

	if len(visited) >= maxNodes {
		sb.WriteString(fmt.Sprintf("\n(truncated at max_nodes=%d)\n", maxNodes))
	}

	return sb.String(), nil
}

// funcRange represents a function's RVA range.
type funcRange struct {
	begin uint32
	end   uint32
	// owner is the function a chained .pdata fragment belongs to (a cold
	// block split off from it); 0 for a function of its own.
	owner uint32
	// exact marks a range read from .pdata rather than estimated.
	exact bool
}

// entry is the start of the function this range's code belongs to.
func (r *funcRange) entry() uint32 {
	if r.owner != 0 {
		return r.owner
	}
	return r.begin
}

// pdataFuncTable is the .pdata table with each chained fragment attributed to
// its function, so a fragment is neither a call-graph node nor a wall that
// cuts the owner's control flow short.
func pdataFuncTable(pd *pdataIndex) []funcRange {
	table := make([]funcRange, len(pd.table))
	for i, fr := range pd.table {
		table[i] = fr
		table[i].owner = pd.primary[fr.begin]
		table[i].exact = true
	}
	return table
}

// paddingStarts finds the functions in the gaps between .pdata ranges --
// leaf functions have no unwind entry -- one after another: a function's
// body is what its control flow reaches, and the next function starts at
// the first code after it (past any int3 padding). A body with a jump the
// walk cannot follow (a switch through a register) runs to the next int3
// padding instead, since its case blocks are unreached code of its own.
func paddingStarts(table []funcRange, execSections []cgSection, mode int, known map[uint32]bool, imageBase uint64) []uint32 {
	knownSorted := make([]uint32, 0, len(known))
	for k := range known {
		knownSorted = append(knownSorted, k)
	}
	sort.Slice(knownSorted, func(i, j int) bool { return knownSorted[i] < knownSorted[j] })
	var out []uint32
	for _, sec := range execSections {
		secEnd := uint64(sec.rva) + uint64(len(sec.data))
		lo := sort.Search(len(table), func(i int) bool { return uint64(table[i].begin) >= uint64(sec.rva) })
		gapFrom := uint64(sec.rva)
		for i := lo; i <= len(table); i++ {
			gapTo := secEnd
			if i < len(table) && uint64(table[i].begin) < secEnd {
				gapTo = uint64(table[i].begin)
			}
			if gapTo > gapFrom {
				data := sec.data[gapFrom-uint64(sec.rva) : gapTo-uint64(sec.rva)]
				walls := map[int]bool{}
				for j := sort.Search(len(knownSorted), func(j int) bool { return uint64(knownSorted[j]) > gapFrom }); j < len(knownSorted) && uint64(knownSorted[j]) < gapTo; j++ {
					walls[int(uint64(knownSorted[j])-gapFrom)] = true
				}
				for _, off := range gapFunctions(data, mode, walls, imageBase+gapFrom) {
					out = append(out, uint32(gapFrom)+uint32(off))
				}
			}
			if i == len(table) || uint64(table[i].begin) >= secEnd {
				break
			}
			gapFrom = max(gapFrom, uint64(table[i].end))
		}
	}
	return out
}

// gapFunctions returns the offsets of the functions laid out in data;
// walls are starts already known, which no body runs into. Between functions
// the compiler pads with int3 (x64) or int3/nop (x86).
func gapFunctions(data []byte, mode int, walls map[int]bool, baseVA uint64) []int {
	isPad := func(b byte) bool { return b == 0xCC || (mode == 32 && b == 0x90) }
	skip := func(i int) int {
		for i < len(data) && isPad(data[i]) {
			i++
		}
		return i
	}
	// nextPadded is the first code after the next run of two or more pad bytes
	// (or a known start): where to resume after bytes that are not code.
	nextPadded := func(i int) int {
		for i < len(data) && !walls[i] && !(isPad(data[i]) && i+1 < len(data) && isPad(data[i+1])) {
			i++
		}
		return skip(i)
	}
	var out []int
	for s := skip(0); s < len(data); {
		end, open := bodyExtent(data, s, mode, walls, baseVA)
		if end == s {
			s = nextPadded(s + 1) // not code (data between functions)
			continue
		}
		out = append(out, s)
		if open {
			// Run on to the next padding (two or more pad bytes in a row).
			for end < len(data) && !walls[end] && !(isPad(data[end]) && end+1 < len(data) && isPad(data[end+1])) {
				end++
			}
		}
		s = skip(end)
	}
	return out
}

// x86SwitchTable reads an x86 MSVC switch, jmp [index*4+table], whose table
// of absolute case addresses was placed in the code after the function. It
// returns the case offsets and the table's extent [from, to) in data; the
// table follows the jump and its cases lie between start and the table.
func x86SwitchTable(data []byte, inst x86asm.Inst, baseVA uint64, start, pos int) ([]int, int, int, bool) {
	m, ok := inst.Args[0].(x86asm.Mem)
	if !ok || m.Base != 0 || m.Index == 0 || m.Scale != 4 || inst.Mode != 32 {
		return nil, 0, 0, false
	}
	tableVA := uint64(uint32(m.Disp))
	if tableVA < baseVA || tableVA-baseVA >= uint64(len(data)) {
		return nil, 0, 0, false
	}
	from := int(tableVA - baseVA)
	if from <= pos {
		return nil, 0, 0, false
	}
	var cases []int
	to := from
	for to+4 <= len(data) && len(cases) < maxJumpTableEntries {
		// Case blocks lie between the function start and the table.
		va := uint64(binary.LittleEndian.Uint32(data[to:]))
		if va < baseVA+uint64(start) || va >= baseVA+uint64(from) {
			break
		}
		cases = append(cases, int(va-baseVA))
		to += 4
	}
	if len(cases) == 0 {
		return nil, 0, 0, false
	}
	return cases, from, to, true
}

// isSwitchJump recognizes a switch dispatch: jmp reg (x64, the target added
// to the image base) or jmp [table+index*scale] (x86, a table of addresses).
// A jmp through a plain memory slot is a tail call (an import or a vtable).
func isSwitchJump(inst x86asm.Inst) bool {
	switch a := inst.Args[0].(type) {
	case x86asm.Reg:
		return true
	case x86asm.Mem:
		return a.Index != 0
	}
	return false
}

// bodyExtent walks the control flow from start and returns the end of the
// code it covers contiguously from start: a jump to distant shared code must
// not swallow the functions in between. Alignment nops the walk skips over
// do not break the run. open reports a switch dispatch it could not follow.
// int3 bytes are walls, and an unconditional jump to code right after int3
// padding is a tail call into another function, not followed.
func bodyExtent(data []byte, start, mode int, walls map[int]bool, baseVA uint64) (int, bool) {
	open := false
	reached := map[int]int{} // instruction start -> end
	stack := []int{start}
	for len(stack) > 0 && len(reached) < 20000 {
		pos := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if pos < start || pos >= len(data) || data[pos] == 0xCC || (pos != start && walls[pos]) {
			continue
		}
		if _, ok := reached[pos]; ok {
			continue
		}
		inst, err := x86asm.Decode(data[pos:], mode)
		if err != nil || inst.Len == 0 {
			continue
		}
		next := pos + inst.Len
		reached[pos] = next
		switch inst.Op {
		case x86asm.RET:
		case x86asm.JMP:
			if t, ok := branchTargetOff(inst, pos); ok {
				if t > 0 && t < len(data) && data[t-1] != 0xCC {
					stack = append(stack, t)
				}
			} else if cases, from, to, ok := x86SwitchTable(data, inst, baseVA, start, pos); ok {
				// The table sits in this code: the body runs over it.
				reached[from] = to
				stack = append(stack, cases...)
			} else if isSwitchJump(inst) {
				open = true
			}
		default:
			if t, ok := branchTargetOff(inst, pos); ok && inst.Op != x86asm.CALL {
				stack = append(stack, t)
			}
			stack = append(stack, next)
		}
	}
	end := start
	for {
		if end != start && walls[end] {
			return end, open
		}
		if e, ok := reached[end]; ok {
			end = e
			continue
		}
		// Skip a hole of nops (loop alignment) when code continues after it.
		n := end
		for n < len(data) && n-end < 16 {
			inst, err := x86asm.Decode(data[n:], mode)
			if err != nil || inst.Op != x86asm.NOP {
				break
			}
			n += inst.Len
		}
		if _, ok := reached[n]; n > end && ok {
			end = n
			continue
		}
		// An instruction reached from a branch may start inside the run's last
		// bytes only on overlapping decodes; anything else ends the body.
		return end, open
	}
}

// addGapStarts adds extra function starts that fall outside every exact
// (.pdata) range: leaf functions have no unwind entry and sit in the gaps.
// Starts inside a .pdata range are branch targets or mid-function labels and
// must not split it; those ranges keep their exact ends. Estimated ranges
// already in the table are re-ranged with the new starts.
func addGapStarts(base []funcRange, extraStarts []uint32, execSections []cgSection) []funcRange {
	var exact []funcRange
	var starts []uint32
	for _, fr := range base {
		if fr.exact {
			exact = append(exact, fr)
		} else {
			starts = append(starts, fr.begin)
		}
	}
	added := false
	for _, s := range extraStarts {
		if findFunc(exact, s) == nil && isInExecSection(execSections, s) {
			starts = append(starts, s)
			added = true
		}
	}
	if !added {
		return base
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
	table := exact
	for i, s := range starts {
		if i > 0 && starts[i-1] == s {
			continue
		}
		end := uint32(0)
		for _, sec := range execSections {
			if se := uint64(sec.rva) + uint64(len(sec.data)); uint64(s) >= uint64(sec.rva) && uint64(s) < se {
				end = uint32(min(se, 0xFFFFFFFF))
			}
		}
		if j := sort.Search(len(exact), func(j int) bool { return exact[j].begin > s }); j < len(exact) && exact[j].begin < end {
			end = exact[j].begin
		}
		for k := i + 1; k < len(starts); k++ {
			if starts[k] != s {
				end = min(end, starts[k])
				break
			}
		}
		if end > s {
			table = append(table, funcRange{begin: s, end: end})
		}
	}
	sort.Slice(table, func(i, j int) bool { return table[i].begin < table[j].begin })
	return table
}

// buildFuncTable extracts all function ranges from .pdata.
// Returns sorted slice for binary search.
func buildFuncTable(f *pe.File, imageBase uint64) []funcRange {
	oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || len(oh64.DataDirectory) <= 3 {
		return nil
	}
	excDir := oh64.DataDirectory[3]
	if excDir.VirtualAddress == 0 || excDir.Size < 12 {
		return nil
	}

	// Read .pdata via section
	var pdataData []byte
	for _, s := range f.Sections {
		if excDir.VirtualAddress >= s.VirtualAddress &&
			excDir.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			secData, err := s.Data()
			if err != nil {
				return nil
			}
			off := excDir.VirtualAddress - s.VirtualAddress
			if uint64(off) >= uint64(len(secData)) {
				return nil
			}
			end64 := uint64(off) + uint64(excDir.Size)
			if end64 > uint64(len(secData)) {
				end64 = uint64(len(secData))
			}
			pdataData = secData[off:end64]
			break
		}
	}
	if len(pdataData) < 12 {
		return nil
	}

	count := len(pdataData) / 12
	if count > 500000 {
		count = 500000
	}

	table := make([]funcRange, 0, count)
	for i := 0; i < count; i++ {
		off := i * 12
		begin := binary.LittleEndian.Uint32(pdataData[off:])
		end := binary.LittleEndian.Uint32(pdataData[off+4:])
		if begin < end {
			table = append(table, funcRange{begin: begin, end: end})
		}
	}

	sort.Slice(table, func(i, j int) bool { return table[i].begin < table[j].begin })
	return table
}

// mergeStartsIntoFuncTable folds extra function starts (e.g. PE exports, which
// the call-target heuristic never sees) into the table as real boundaries. The
// union of starts is re-ranged as [start_i, start_{i+1}) within each section, so
// an ordinal-only export (D2*.dll) is no longer folded into a neighbouring call
// target -- fixing both root resolution and function extents for call_graph.
func mergeStartsIntoFuncTable(base []funcRange, extraStarts []uint32, execSections []cgSection) []funcRange {
	startSet := make(map[uint32]bool, len(base)+len(extraStarts))
	for _, fr := range base {
		startSet[fr.begin] = true
	}
	for _, s := range extraStarts {
		if isInExecSection(execSections, s) {
			startSet[s] = true
		}
	}
	starts := make([]uint32, 0, len(startSet))
	for s := range startSet {
		starts = append(starts, s)
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })

	table := make([]funcRange, 0, len(starts))
	for i, s := range starts {
		var secEnd uint32
		for _, sec := range execSections {
			if uint64(s) >= uint64(sec.rva) && uint64(s) < uint64(sec.rva)+uint64(len(sec.data)) {
				// Cap like the sibling table builders so a section near the 4GB
				// edge can't wrap and silently drop the start.
				se64 := uint64(sec.rva) + uint64(len(sec.data))
				if se64 > 0xFFFFFFFF {
					se64 = 0xFFFFFFFF
				}
				secEnd = uint32(se64)
				break
			}
		}
		end := secEnd
		if i+1 < len(starts) && starts[i+1] > s && starts[i+1] < secEnd {
			end = starts[i+1]
		}
		if end > s {
			table = append(table, funcRange{begin: s, end: end})
		}
	}
	return table
}

// isInExecSection checks if an RVA falls within any executable section.
// Used to filter false positive CALL targets that land outside code.
func isInExecSection(sections []cgSection, rva uint32) bool {
	for _, sec := range sections {
		if uint64(rva) >= uint64(sec.rva) && uint64(rva) < uint64(sec.rva)+uint64(len(sec.data)) {
			return true
		}
	}
	return false
}

// findFunc finds the function containing rva via binary search on the func table.
func findFunc(table []funcRange, rva uint32) *funcRange {
	idx := sort.Search(len(table), func(i int) bool { return table[i].begin > rva })
	if idx == 0 {
		return nil
	}
	fn := &table[idx-1]
	if rva >= fn.begin && rva < fn.end {
		return fn
	}
	return nil
}

// cgCallTarget represents a call target found by the call scanners.
type cgCallTarget struct {
	rva      uint32
	indirect bool // true = FF 15 [rip+disp32] (IAT slot), false = E8 rel32 (direct)
}

// scanCallTargetsCFG collects a function's CALL targets by walking its control
// flow from funcBegin instead of linearly scanning a [begin,end] byte range.
// It follows fallthrough and direct branch targets, stops at returns / indirect
// or unconditional jumps that leave the function, and walls off other known
// function starts. This prevents the classic mis-attribution where an
// over-extended heuristic funcEnd makes the linear scan walk into the NEXT
// function and report ITS calls as edges of this one ("fall-through" edges).
func scanCallTargetsCFG(sections []cgSection, funcBegin uint32, imageBase uint64, is64 bool, starts map[uint32]bool) []cgCallTarget {
	mode := 32
	if is64 {
		mode = 64
	}
	var data []byte
	var secRVA uint32
	found := false
	for _, sec := range sections {
		if uint64(funcBegin) >= uint64(sec.rva) && uint64(funcBegin) < uint64(sec.rva)+uint64(len(sec.data)) {
			data, secRVA, found = sec.data, sec.rva, true
			break
		}
	}
	if !found {
		return nil
	}

	startOff := int(funcBegin - secRVA)
	seen := make(map[uint32]bool)
	var targets []cgCallTarget
	visited := make(map[int]bool)
	stack := []int{startOff}
	budget := 200000

	for len(stack) > 0 && budget > 0 {
		pos := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if pos < 0 || pos >= len(data) || visited[pos] {
			continue
		}
		rva := secRVA + uint32(pos)
		if pos != startOff && starts[rva] {
			continue // reached another function -- not part of this one
		}
		visited[pos] = true
		budget--

		inst, err := x86asm.Decode(data[pos:], mode)
		if err != nil || inst.Len == 0 {
			continue
		}
		next := pos + inst.Len

		switch {
		case data[pos] == 0xE8 && inst.Len == 5:
			t := uint32(int64(rva) + 5 + int64(int32(binary.LittleEndian.Uint32(data[pos+1:]))))
			if !seen[t] {
				seen[t] = true
				targets = append(targets, cgCallTarget{rva: t, indirect: false})
			}
		case data[pos] == 0xFF && inst.Len >= 6 && data[pos+1] == 0x15:
			var t uint32
			valid := false
			if is64 {
				t = uint32(int64(rva) + int64(inst.Len) + int64(int32(binary.LittleEndian.Uint32(data[pos+2:pos+6]))))
				valid = true
			} else if addr := binary.LittleEndian.Uint32(data[pos+2 : pos+6]); addr >= uint32(imageBase) {
				t = addr - uint32(imageBase)
				valid = true
			}
			if valid && !seen[t] {
				seen[t] = true
				targets = append(targets, cgCallTarget{rva: t, indirect: true})
			}
		}

		if data[pos] == 0xCC {
			continue // int3 padding -- stop, don't collect a neighbour's calls
		}
		switch inst.Op {
		case x86asm.RET, x86asm.LRET, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ:
			// terminator
		case x86asm.JMP:
			if to, ok := branchTargetOff(inst, pos); ok {
				stack = append(stack, to)
			}
		case x86asm.CALL, x86asm.LCALL:
			stack = append(stack, next)
		default:
			if to, ok := branchTargetOff(inst, pos); ok {
				stack = append(stack, to)
			}
			stack = append(stack, next)
		}
	}

	sort.Slice(targets, func(i, j int) bool { return targets[i].rva < targets[j].rva })
	return targets
}

// cgCaller is a function that reaches the root: by a CALL, by a tail JMP, or
// through a thunk (a function that only jumps to the root).
type cgCaller struct {
	rva   uint32 // the caller's entry
	tail  bool   // reaches it with JMP rel32
	thunk uint32 // non-zero: calls this thunk, which jumps to the root
}

// findCallers lists the functions with a CALL or JMP rel32 to targetRVA,
// matching every byte offset: a linear decode of the whole section loses
// sync at the first data island and skips the calls after it. A caller that
// is itself a thunk (its entry is the jump) is replaced by its own callers.
func findCallers(sections []cgSection, targetRVA uint32, funcTable []funcRange) []cgCaller {
	var out []cgCaller
	seen := map[uint32]bool{}
	for _, c := range relCallers(sections, targetRVA, funcTable) {
		if c.tail && c.site == c.rva {
			for _, t := range relCallers(sections, c.rva, funcTable) {
				if !seen[t.rva] {
					seen[t.rva] = true
					out = append(out, cgCaller{rva: t.rva, tail: t.tail, thunk: c.rva})
				}
			}
			continue
		}
		if !seen[c.rva] {
			seen[c.rva] = true
			out = append(out, cgCaller{rva: c.rva, tail: c.tail})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rva < out[j].rva })
	return out
}

type relCaller struct {
	rva, site uint32
	tail      bool
}

// relCallers finds E8/E9 rel32 instructions that land on target, attributed
// to the function (entry) containing each.
func relCallers(sections []cgSection, target uint32, funcTable []funcRange) []relCaller {
	var out []relCaller
	for _, sec := range sections {
		data := sec.data
		for i := 0; i+5 <= len(data); i++ {
			if data[i] != 0xE8 && data[i] != 0xE9 {
				continue
			}
			site := sec.rva + uint32(i)
			rel := int32(binary.LittleEndian.Uint32(data[i+1:]))
			if uint32(int64(site)+5+int64(rel)) != target {
				continue
			}
			fn := findFunc(funcTable, site)
			if fn == nil {
				continue
			}
			out = append(out, relCaller{rva: fn.entry(), site: site, tail: data[i] == 0xE9})
		}
	}
	return out
}

// funcName formats a VA with symbol name if available.
func funcName(va uint64, symbols map[uint64]string) string {
	if name, ok := symbols[va]; ok {
		return fmt.Sprintf("0x%x %s", va, name)
	}
	return fmt.Sprintf("0x%x", va)
}

// printCallTree recursively prints the call tree with indentation.
// imports maps caller VA -> list of imported API names (from FF 15 indirect calls).
func printCallTree(sb *strings.Builder, va uint64, edges []cgEdge, imports map[uint64][]string, symbols map[uint64]string, curDepth, maxDepth int, printed map[uint64]bool) {
	indent := strings.Repeat("  ", curDepth)
	name := funcName(va, symbols)

	if printed[va] {
		sb.WriteString(fmt.Sprintf("%s-> %s (already shown)\n", indent, name))
		return
	}

	if curDepth == 0 {
		sb.WriteString(fmt.Sprintf("%s%s\n", indent, name))
	}
	printed[va] = true

	if curDepth >= maxDepth {
		return
	}

	// Find children (direct calls)
	var children []uint64
	childSeen := make(map[uint64]bool)
	for _, e := range edges {
		if e.callerVA == va && !childSeen[e.calleeVA] {
			childSeen[e.calleeVA] = true
			children = append(children, e.calleeVA)
		}
	}

	for _, child := range children {
		childName := funcName(child, symbols)
		if printed[child] {
			sb.WriteString(fmt.Sprintf("%s  -> %s (already shown)\n", indent, childName))
		} else {
			sb.WriteString(fmt.Sprintf("%s  -> %s\n", indent, childName))
			printCallTree(sb, child, edges, imports, symbols, curDepth+1, maxDepth, printed)
		}
	}

	// Show imported API calls (indirect via IAT)
	if apiNames, ok := imports[va]; ok && len(apiNames) > 0 {
		for _, apiName := range apiNames {
			sb.WriteString(fmt.Sprintf("%s  -> %s [IAT]\n", indent, apiName))
		}
	}
}

// buildFuncTableFromCalls detects x86 function boundaries heuristically
// by collecting all E8 CALL targets that land in executable sections.
// Each target is assumed to be a function entry; the function extends
// until the next detected entry or section end.
func buildFuncTableFromCalls(sections []cgSection, imageBase uint64) []funcRange {
	// Step 1: collect unique E8 CALL targets via instruction-level scan
	starts := make(map[uint32]bool)
	for _, sec := range sections {
		data := sec.data
		for i := 0; i < len(data); {
			inst, err := x86asm.Decode(data[i:], 32)
			if err != nil || inst.Len <= 0 {
				i++
				continue
			}
			if data[i] == 0xE8 && inst.Len == 5 {
				instrRVA := sec.rva + uint32(i)
				rel := int32(binary.LittleEndian.Uint32(data[i+1:]))
				target := uint32(int64(instrRVA) + 5 + int64(rel))
				if isInExecSection(sections, target) {
					starts[target] = true
				}
			}
			i += inst.Len
		}
	}

	if len(starts) == 0 {
		return nil
	}

	// Step 2: sort unique function starts
	sorted := make([]uint32, 0, len(starts))
	for s := range starts {
		sorted = append(sorted, s)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	// Step 3: build funcRange -- end = min(next func start, section end)
	table := make([]funcRange, 0, len(sorted))
	for i, begin := range sorted {
		// Find section boundary for this function
		var secEnd uint32
		for _, sec := range sections {
			se64 := uint64(sec.rva) + uint64(len(sec.data))
			if se64 > 0xFFFFFFFF {
				se64 = 0xFFFFFFFF
			}
			if uint64(begin) >= uint64(sec.rva) && uint64(begin) < se64 {
				secEnd = uint32(se64)
				break
			}
		}
		if secEnd <= begin {
			continue
		}

		var end uint32
		if i+1 < len(sorted) && sorted[i+1] < secEnd {
			// Next function is within same section
			end = sorted[i+1]
		} else {
			// Last function in section or next function is in different section
			end = secEnd
		}
		if end > begin {
			table = append(table, funcRange{begin: begin, end: end})
		}
	}

	return table
}

// insertFunc adds a function entry at rva into a sorted funcTable,
// splitting an existing range if necessary. Used when the root VA
// is not a known CALL target (e.g. entry point, indirect call target).
func insertFunc(table []funcRange, rva uint32, sections []cgSection) []funcRange {
	// Already in table as a function start?
	if fn := findFunc(table, rva); fn != nil && fn.begin == rva {
		return table
	}

	// Find end: next function start after rva, or section end
	var end uint32
	idx := sort.Search(len(table), func(i int) bool { return table[i].begin > rva })
	if idx < len(table) {
		end = table[idx].begin
	} else {
		for _, sec := range sections {
			secEnd64 := uint64(sec.rva) + uint64(len(sec.data))
			if uint64(rva) >= uint64(sec.rva) && uint64(rva) < secEnd64 {
				if secEnd64 > 0xFFFFFFFF {
					secEnd64 = 0xFFFFFFFF
				}
				end = uint32(secEnd64)
				break
			}
		}
	}
	if end <= rva {
		return table
	}

	// Insert and re-sort
	table = append(table, funcRange{begin: rva, end: end})
	sort.Slice(table, func(i, j int) bool { return table[i].begin < table[j].begin })

	// Fix previous entry's end if it was split (re-find after sort)
	newIdx := sort.Search(len(table), func(i int) bool { return table[i].begin >= rva })
	if newIdx > 0 && table[newIdx-1].end > rva {
		table[newIdx-1].end = rva
	}

	return table
}

// cgBinary holds parsed binary info for call graph analysis.
type cgBinary struct {
	imageBase      uint64
	is64           bool
	arch           string // "x86" or "x64"
	format         string // "PE", "ELF", "Mach-O"
	symbols        map[uint64]string
	execSections   []cgSection
	staticSections []cgSection // mapped, non-writable bytes safe for constant loads
	funcTable      []funcRange
	// innerStarts are estimated starts (sweep, exports, data pointers) that
	// fall inside a .pdata range and so are not in funcTable. The decompile
	// host still takes them as known starts, as it did before .pdata ranges
	// were kept exact; its Ghidra comparisons were measured with them.
	innerStarts []uint32
	// layoutStarts are table entries found only from the padding layout; the
	// decompile host leaves them out for the same reason.
	layoutStarts map[uint32]bool
	closer       func()
}

// cgOpenBinary tries PE, ELF, Mach-O in order and returns a cgBinary. A PE's
// matching PDB adds function and data names the file itself lacks.
func cgOpenBinary(path string) (*cgBinary, error) { return cgOpenBinaryPDB(path, true) }

// cgOpenBinaryPDB is cgOpenBinary with PDB names optional: the decompile
// worker reads the PDB in full itself and keeps import slots and code names
// apart, which merged names would blur.
func cgOpenBinaryPDB(path string, withPDB bool) (*cgBinary, error) {
	// Try PE first
	if bin, err := cgOpenPE(path, withPDB); err == nil {
		return bin, nil
	}
	// Try ELF
	if bin, err := cgOpenELF(path); err == nil {
		return bin, nil
	}
	// Try Mach-O
	if bin, err := cgOpenMachO(path); err == nil {
		return bin, nil
	}
	return nil, fmt.Errorf("cannot open %s as PE/ELF/Mach-O", path)
}

// cgOpenPE opens a PE binary and extracts call graph info.
func cgOpenPE(path string, withPDB bool) (*cgBinary, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}

	imageBase := peImageBase(f)
	if imageBase == 0 {
		f.Close()
		return nil, fmt.Errorf("PE: no optional header")
	}

	var is64 bool
	switch f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		is64 = true
	}

	arch := "x86"
	if is64 {
		arch = "x64"
	}

	// Load executable sections
	var execSections []cgSection
	var staticSections []cgSection
	for _, s := range f.Sections {
		if s.Characteristics&0x40000000 != 0 && s.Characteristics&0x80000000 == 0 { // readable, not writable
			if data, dataErr := s.Data(); dataErr == nil && len(data) > 0 {
				staticSections = append(staticSections, cgSection{rva: s.VirtualAddress, data: data})
			}
		}
		if s.Characteristics&0x20000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
			data, err := s.Data()
			if err != nil {
				continue
			}
			execSections = append(execSections, cgSection{rva: s.VirtualAddress, data: data})
		}
	}
	if len(execSections) == 0 {
		f.Close()
		return nil, fmt.Errorf("PE: no executable sections")
	}

	// Build function table. With .pdata the boundaries are exact and the
	// extra starts below only fill the gaps (leaf functions); without it they
	// are all estimates and re-range one another.
	var funcTable []funcRange
	authoritative := false
	var innerStarts []uint32
	merge := func(starts []uint32) {
		if authoritative {
			for _, s := range starts {
				if fn := findFunc(funcTable, s); fn != nil && fn.begin != s {
					innerStarts = append(innerStarts, s)
				}
			}
			funcTable = addGapStarts(funcTable, starts, execSections)
		} else {
			funcTable = mergeStartsIntoFuncTable(funcTable, starts, execSections)
		}
	}
	if is64 {
		if pd := loadPdata(f, imageBase); pd != nil {
			funcTable, authoritative = pdataFuncTable(pd), true
		}
		if len(funcTable) == 0 {
			// x64 PE without .pdata: fall back to heuristic
			funcTable = buildFuncTableFromCalls(execSections, imageBase)
		}
	} else {
		// x86 PE: no .pdata, use heuristic
		funcTable = buildFuncTableFromCalls(execSections, imageBase)
	}

	// Fold export starts in as real boundaries -- the heuristic table is built
	// from CALL targets only and would otherwise miss ordinal-only exports.
	if exp, _ := codeExportStarts(f); len(exp) > 0 {
		merge(exp)
	}
	// Fold in vtable/callback function pointers so virtual-only functions become
	// real boundaries (and valid call_graph roots), not folded into a neighbour.
	if ptrs := dataPointerStarts(f, imageBase, is64); len(ptrs) > 0 {
		merge(ptrs)
	}
	// Fold in a full linear sweep's corroborated CALL/JMP targets, so functions
	// whose callers are unreachable from the exports are still real boundaries.
	sweepMode := 32
	if is64 {
		sweepMode = 64
	}
	var sweep []uint32
	id := fileIdentity(path)
	for _, sec := range execSections {
		sweep = append(sweep, cachedSweepStarts(id, sec.data, sec.rva, sweepMode)...)
	}
	if len(sweep) > 0 {
		merge(sweep)
	}
	// Functions nothing above found, located from the code layout: in the
	// gaps between .pdata ranges, or (x86) across the whole code. Only the
	// starts no other source knows are marked as layout-only.
	var exact []funcRange
	for _, fr := range funcTable {
		if fr.exact {
			exact = append(exact, fr)
		}
	}
	known := make(map[uint32]bool, len(funcTable)+len(innerStarts))
	for _, fr := range funcTable {
		known[fr.begin] = true
	}
	for _, s := range innerStarts {
		known[s] = true
	}
	pads := paddingStarts(exact, execSections, sweepMode, known, imageBase)
	layoutStarts := make(map[uint32]bool, len(pads))
	for _, s := range pads {
		if !known[s] {
			layoutStarts[s] = true
		}
	}
	merge(pads)

	symbols := peSymbolMap(f, imageBase)
	if withPDB {
		mergePDBNames(symbols, path, "", false, f, imageBase)
	}

	return &cgBinary{
		imageBase:      imageBase,
		is64:           is64,
		arch:           arch,
		format:         "PE",
		symbols:        symbols,
		execSections:   execSections,
		staticSections: staticSections,
		funcTable:      funcTable,
		innerStarts:    innerStarts,
		layoutStarts:   layoutStarts,
		closer:         func() { f.Close() },
	}, nil
}

// cgOpenELF opens an ELF binary and extracts call graph info.
func cgOpenELF(path string) (*cgBinary, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}

	var is64 bool
	var arch string
	switch f.Machine {
	case elf.EM_386:
		arch = "x86"
	case elf.EM_X86_64:
		arch = "x64"
		is64 = true
	case elf.EM_AARCH64:
		arch = "arm64"
		is64 = true
	case elf.EM_ARM:
		arch = "arm32"
	default:
		f.Close()
		return nil, fmt.Errorf("ELF: unsupported machine %v", f.Machine)
	}

	// ELF imageBase = lowest PT_LOAD virtual address. Unlike PE (which stores
	// imageBase in the optional header), ELF uses the first loadable segment's
	// vaddr as the base for RVA calculations.
	var imageBase uint64 = ^uint64(0)
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Vaddr < imageBase {
			imageBase = p.Vaddr
		}
	}
	if imageBase == ^uint64(0) {
		imageBase = 0
	}

	// Executable sections (SHF_EXECINSTR)
	var execSections []cgSection
	var staticSections []cgSection
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_ALLOC != 0 && s.Flags&elf.SHF_WRITE == 0 && s.Size > 0 && s.Addr >= imageBase {
			if data, dataErr := s.Data(); dataErr == nil && len(data) > 0 {
				if rva64 := s.Addr - imageBase; rva64 <= 0xFFFFFFFF {
					staticSections = append(staticSections, cgSection{rva: uint32(rva64), data: data})
				}
			}
		}
		if s.Flags&elf.SHF_EXECINSTR != 0 && s.Size > 0 {
			data, err := s.Data()
			if err != nil || len(data) == 0 {
				continue
			}
			// Guard: s.Addr < imageBase would cause uint64 underflow in subtraction
			if s.Addr < imageBase {
				continue
			}
			rva64 := s.Addr - imageBase
			// RVA must fit in uint32 for cgSection.rva and all scan functions
			if rva64 > 0xFFFFFFFF {
				continue
			}
			execSections = append(execSections, cgSection{rva: uint32(rva64), data: data})
		}
	}
	if len(execSections) == 0 {
		f.Close()
		return nil, fmt.Errorf("ELF: no executable sections")
	}

	// Heuristic function table from CALL/BL targets
	var funcTable []funcRange
	switch arch {
	case "arm64":
		funcTable = buildFuncTableFromCallsARM64(execSections, imageBase)
	case "arm32":
		funcTable = buildFuncTableFromCallsARM32(execSections, imageBase)
	default:
		funcTable = buildFuncTableFromCalls(execSections, imageBase)
	}

	// Merge ELF symbol table entries as function starts. Heuristic CALL-target
	// detection alone misses functions only reached via indirect calls, jump
	// tables, or tail calls. Symbol tables provide authoritative entry points.
	symbols := elfSymbolMap(f, imageBase)
	if len(symbols) > 0 {
		for va := range symbols {
			if va < imageBase {
				continue
			}
			rva64 := va - imageBase
			if rva64 > 0xFFFFFFFF {
				continue // symbol beyond uint32 RVA range
			}
			rva := uint32(rva64)
			if isInExecSection(execSections, rva) {
				if fn := findFunc(funcTable, rva); fn == nil || fn.begin != rva {
					funcTable = insertFunc(funcTable, rva, execSections)
				}
			}
		}
	}

	return &cgBinary{
		imageBase:      imageBase,
		is64:           is64,
		arch:           arch,
		format:         "ELF",
		symbols:        symbols,
		execSections:   execSections,
		staticSections: staticSections,
		funcTable:      funcTable,
		closer:         func() { f.Close() },
	}, nil
}

// cgOpenMachO opens a Mach-O binary and extracts call graph info.
func cgOpenMachO(path string) (*cgBinary, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, err
	}

	var is64 bool
	var arch string
	switch f.Cpu {
	case macho.Cpu386:
		arch = "x86"
	case macho.CpuAmd64:
		arch = "x64"
		is64 = true
	case macho.CpuArm64:
		arch = "arm64"
		is64 = true
	case macho.CpuArm:
		arch = "arm32"
	default:
		f.Close()
		return nil, fmt.Errorf("Mach-O: unsupported CPU %v", f.Cpu)
	}

	// Mach-O imageBase = __TEXT segment virtual address. This is the conventional
	// base for Mach-O binaries; all code sections live within __TEXT.
	var imageBase uint64
	for _, seg := range f.Loads {
		if s, ok := seg.(*macho.Segment); ok && s.Name == "__TEXT" {
			imageBase = s.Addr
			break
		}
	}

	// Executable sections (in __TEXT segment)
	var execSections []cgSection
	var staticSections []cgSection
	for _, s := range f.Sections {
		if (s.Seg == "__TEXT" || s.Seg == "__DATA_CONST") && s.Size > 0 && s.Addr >= imageBase {
			if data, dataErr := s.Data(); dataErr == nil && len(data) > 0 {
				if rva64 := s.Addr - imageBase; rva64 <= 0xFFFFFFFF {
					staticSections = append(staticSections, cgSection{rva: uint32(rva64), data: data})
				}
			}
		}
		if s.Seg == "__TEXT" && s.Size > 0 {
			data, err := s.Data()
			if err != nil || len(data) == 0 {
				continue
			}
			// Guard: s.Addr < imageBase would cause uint64 underflow in subtraction
			if s.Addr < imageBase {
				continue
			}
			rva64 := s.Addr - imageBase
			// RVA must fit in uint32 for cgSection.rva and all scan functions
			if rva64 > 0xFFFFFFFF {
				continue
			}
			execSections = append(execSections, cgSection{rva: uint32(rva64), data: data})
		}
	}
	if len(execSections) == 0 {
		f.Close()
		return nil, fmt.Errorf("Mach-O: no executable sections")
	}

	// Heuristic function table from CALL/BL targets
	var funcTable []funcRange
	switch arch {
	case "arm64":
		funcTable = buildFuncTableFromCallsARM64(execSections, imageBase)
	case "arm32":
		funcTable = buildFuncTableFromCallsARM32(execSections, imageBase)
	default:
		funcTable = buildFuncTableFromCalls(execSections, imageBase)
	}

	// Merge Mach-O symbol table entries as function starts (same rationale as ELF)
	symbols := machoSymbolMap(f, imageBase)
	if len(symbols) > 0 {
		for va := range symbols {
			if va < imageBase {
				continue
			}
			rva64 := va - imageBase
			if rva64 > 0xFFFFFFFF {
				continue // symbol beyond uint32 RVA range
			}
			rva := uint32(rva64)
			if isInExecSection(execSections, rva) {
				if fn := findFunc(funcTable, rva); fn == nil || fn.begin != rva {
					funcTable = insertFunc(funcTable, rva, execSections)
				}
			}
		}
	}

	return &cgBinary{
		imageBase:      imageBase,
		is64:           is64,
		arch:           arch,
		format:         "Mach-O",
		symbols:        symbols,
		execSections:   execSections,
		staticSections: staticSections,
		funcTable:      funcTable,
		closer:         func() { f.Close() },
	}, nil
}

// elfSymbolMap builds a VA->name map from ELF .symtab and .dynsym.
func elfSymbolMap(f *elf.File, imageBase uint64) map[uint64]string {
	m := make(map[uint64]string)
	// .symtab
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			if s.Name != "" && s.Value != 0 {
				m[s.Value] = s.Name
			}
		}
	}
	// .dynsym
	if syms, err := f.DynamicSymbols(); err == nil {
		for _, s := range syms {
			if s.Name != "" && s.Value != 0 {
				if _, exists := m[s.Value]; !exists {
					m[s.Value] = s.Name
				}
			}
		}
	}
	return m
}

// machoSymbolMap builds a VA->name map from Mach-O symbol table.
func machoSymbolMap(f *macho.File, imageBase uint64) map[uint64]string {
	m := make(map[uint64]string)
	if f.Symtab == nil {
		return m
	}
	for _, s := range f.Symtab.Syms {
		if s.Name != "" && s.Value != 0 {
			m[s.Value] = s.Name
		}
	}
	return m
}

// --- ARM64 call graph support ---

// buildFuncTableFromCallsARM64 detects function boundaries by collecting
// BL (Branch with Link) targets that land in executable sections.
func buildFuncTableFromCallsARM64(sections []cgSection, imageBase uint64) []funcRange {
	starts := make(map[uint32]bool)
	for _, sec := range sections {
		data := sec.data
		for i := 0; i+4 <= len(data); i += 4 {
			instr := binary.LittleEndian.Uint32(data[i:])
			// BL imm26: 1001 01ii iiii iiii iiii iiii iiii iiii
			if instr>>26 != 0x25 {
				continue
			}
			instrRVA := sec.rva + uint32(i)
			instrVA := imageBase + uint64(instrRVA)
			imm26 := int32(instr&0x03FFFFFF) << 6 >> 6
			targetVA := instrVA + uint64(int64(imm26)*4)
			if targetVA < imageBase {
				continue
			}
			tRVA64 := targetVA - imageBase
			if tRVA64 > 0xFFFFFFFF {
				continue
			}
			target := uint32(tRVA64)
			if isInExecSection(sections, target) {
				starts[target] = true
			}
		}
	}
	return buildFuncRangesFromStarts(starts, sections)
}

// buildFuncTableFromCallsARM32 detects function boundaries by collecting
// BL (Branch with Link) targets. Uses PC+8 pipeline offset for ARM32.
func buildFuncTableFromCallsARM32(sections []cgSection, imageBase uint64) []funcRange {
	starts := make(map[uint32]bool)
	for _, sec := range sections {
		data := sec.data
		for i := 0; i+4 <= len(data); i += 4 {
			instr := binary.LittleEndian.Uint32(data[i:])
			// BL imm24: cccc 1011 iiii iiii iiii iiii iiii iiii
			// Skip cond==0xF: unconditional extension space (BLX uses different
			// target calc with H-bit halfword offset, not handled here)
			if instr>>28 == 0x0F {
				continue
			}
			if (instr>>24)&0x0F != 0x0B {
				continue
			}
			instrRVA := sec.rva + uint32(i)
			instrVA := imageBase + uint64(instrRVA)
			imm24 := int32(instr&0x00FFFFFF) << 8 >> 8
			// ARM32 PC = instrAddr + 8 (pipeline offset)
			targetVA := instrVA + 8 + uint64(int64(imm24)*4)
			if targetVA < imageBase {
				continue
			}
			tRVA64 := targetVA - imageBase
			if tRVA64 > 0xFFFFFFFF {
				continue
			}
			target := uint32(tRVA64)
			if isInExecSection(sections, target) {
				starts[target] = true
			}
		}
	}
	return buildFuncRangesFromStarts(starts, sections)
}

// buildFuncRangesFromStarts converts a set of function start RVAs into
// sorted funcRange slice. Shared by ARM64 and ARM32 table builders.
func buildFuncRangesFromStarts(starts map[uint32]bool, sections []cgSection) []funcRange {
	if len(starts) == 0 {
		return nil
	}
	sorted := make([]uint32, 0, len(starts))
	for s := range starts {
		sorted = append(sorted, s)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	table := make([]funcRange, 0, len(sorted))
	for i, begin := range sorted {
		var secEnd uint32
		for _, sec := range sections {
			se64 := uint64(sec.rva) + uint64(len(sec.data))
			if se64 > 0xFFFFFFFF {
				se64 = 0xFFFFFFFF
			}
			if uint64(begin) >= uint64(sec.rva) && uint64(begin) < se64 {
				secEnd = uint32(se64)
				break
			}
		}
		if secEnd <= begin {
			continue
		}
		var end uint32
		if i+1 < len(sorted) && sorted[i+1] < secEnd {
			end = sorted[i+1]
		} else {
			end = secEnd
		}
		if end > begin {
			table = append(table, funcRange{begin: begin, end: end})
		}
	}
	return table
}

// scanCallTargetsARM64 extracts BL target RVAs from an ARM64 function's code.
func scanCallTargetsARM64(sections []cgSection, funcBegin, funcEnd uint32, imageBase uint64) []cgCallTarget {
	seen := make(map[uint32]bool)
	var targets []cgCallTarget

	for _, sec := range sections {
		secEnd64 := uint64(sec.rva) + uint64(len(sec.data))
		if secEnd64 > 0xFFFFFFFF {
			secEnd64 = 0xFFFFFFFF
		}
		scanStart := funcBegin
		if scanStart < sec.rva {
			scanStart = sec.rva
		}
		scanEnd := funcEnd
		if uint64(scanEnd) > secEnd64 {
			scanEnd = uint32(secEnd64)
		}
		if scanStart >= scanEnd {
			continue
		}

		data := sec.data[scanStart-sec.rva : scanEnd-sec.rva]
		for i := 0; i+4 <= len(data); i += 4 {
			instr := binary.LittleEndian.Uint32(data[i:])
			// BL imm26
			if instr>>26 != 0x25 {
				continue
			}
			instrRVA := scanStart + uint32(i)
			instrVA := imageBase + uint64(instrRVA)
			imm26 := int32(instr&0x03FFFFFF) << 6 >> 6
			targetVA := instrVA + uint64(int64(imm26)*4)
			if targetVA < imageBase {
				continue
			}
			tRVA64 := targetVA - imageBase
			if tRVA64 > 0xFFFFFFFF {
				continue
			}
			target := uint32(tRVA64)
			if !seen[target] {
				seen[target] = true
				targets = append(targets, cgCallTarget{rva: target, indirect: false})
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].rva < targets[j].rva })
	return targets
}

// scanCallTargetsARM32 extracts BL target RVAs from an ARM32 function's code.
func scanCallTargetsARM32(sections []cgSection, funcBegin, funcEnd uint32, imageBase uint64) []cgCallTarget {
	seen := make(map[uint32]bool)
	var targets []cgCallTarget

	for _, sec := range sections {
		secEnd64 := uint64(sec.rva) + uint64(len(sec.data))
		if secEnd64 > 0xFFFFFFFF {
			secEnd64 = 0xFFFFFFFF
		}
		scanStart := funcBegin
		if scanStart < sec.rva {
			scanStart = sec.rva
		}
		scanEnd := funcEnd
		if uint64(scanEnd) > secEnd64 {
			scanEnd = uint32(secEnd64)
		}
		if scanStart >= scanEnd {
			continue
		}

		data := sec.data[scanStart-sec.rva : scanEnd-sec.rva]
		for i := 0; i+4 <= len(data); i += 4 {
			instr := binary.LittleEndian.Uint32(data[i:])
			// Skip cond==0xF: unconditional extension space (BLX uses different
			// target calc with H-bit halfword offset, not handled here)
			if instr>>28 == 0x0F {
				continue
			}
			// BL imm24: cccc 1011 ...
			if (instr>>24)&0x0F != 0x0B {
				continue
			}
			instrRVA := scanStart + uint32(i)
			instrVA := imageBase + uint64(instrRVA)
			imm24 := int32(instr&0x00FFFFFF) << 8 >> 8
			targetVA := instrVA + 8 + uint64(int64(imm24)*4)
			if targetVA < imageBase {
				continue
			}
			tRVA64 := targetVA - imageBase
			if tRVA64 > 0xFFFFFFFF {
				continue
			}
			target := uint32(tRVA64)
			if !seen[target] {
				seen[target] = true
				targets = append(targets, cgCallTarget{rva: target, indirect: false})
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].rva < targets[j].rva })
	return targets
}

// findCallersARM64 scans all executable code for BL instructions targeting funcBeginRVA.
func findCallersARM64(sections []cgSection, targetRVA uint32, imageBase uint64, funcTable []funcRange) []uint32 {
	targetVA := imageBase + uint64(targetRVA)
	seen := make(map[uint32]bool)
	var callers []uint32

	for _, sec := range sections {
		data := sec.data
		for i := 0; i+4 <= len(data); i += 4 {
			instr := binary.LittleEndian.Uint32(data[i:])
			if instr>>26 != 0x25 {
				continue
			}
			instrRVA := sec.rva + uint32(i)
			instrVA := imageBase + uint64(instrRVA)
			imm26 := int32(instr&0x03FFFFFF) << 6 >> 6
			blTarget := instrVA + uint64(int64(imm26)*4)
			if blTarget == targetVA {
				fn := findFunc(funcTable, instrRVA)
				if fn != nil && !seen[fn.begin] {
					seen[fn.begin] = true
					callers = append(callers, fn.begin)
				}
			}
		}
	}
	sort.Slice(callers, func(i, j int) bool { return callers[i] < callers[j] })
	return callers
}

// findCallersARM32 scans all executable code for BL instructions targeting funcBeginRVA.
func findCallersARM32(sections []cgSection, targetRVA uint32, imageBase uint64, funcTable []funcRange) []uint32 {
	targetVA := imageBase + uint64(targetRVA)
	seen := make(map[uint32]bool)
	var callers []uint32

	for _, sec := range sections {
		data := sec.data
		for i := 0; i+4 <= len(data); i += 4 {
			instr := binary.LittleEndian.Uint32(data[i:])
			// Skip cond==0xF: unconditional extension space (BLX)
			if instr>>28 == 0x0F {
				continue
			}
			if (instr>>24)&0x0F != 0x0B {
				continue
			}
			instrRVA := sec.rva + uint32(i)
			instrVA := imageBase + uint64(instrRVA)
			imm24 := int32(instr&0x00FFFFFF) << 8 >> 8
			blTarget := instrVA + 8 + uint64(int64(imm24)*4)
			if blTarget == targetVA {
				fn := findFunc(funcTable, instrRVA)
				if fn != nil && !seen[fn.begin] {
					seen[fn.begin] = true
					callers = append(callers, fn.begin)
				}
			}
		}
	}
	sort.Slice(callers, func(i, j int) bool { return callers[i] < callers[j] })
	return callers
}
