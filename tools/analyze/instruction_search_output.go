package analyze

import (
	"fmt"
	"iter"
	"math/bits"
	"sort"
	"strings"
	"unicode/utf8"

	"agent-tool/common"

	"golang.org/x/arch/x86/x86asm"
)

type instructionSearchRow struct {
	rva        uint32
	confidence string
	trace      string
}

func (b *rvaBits) addresses(yield func(uint32) bool) {
	if b == nil {
		return
	}
	for i, section := range b.bits {
		for j, word := range section {
			for word != 0 {
				rva := b.secs[i].rva + uint32(j*64+bits.TrailingZeros64(word))
				if !yield(rva) {
					return
				}
				word &= word - 1
			}
		}
	}
}

func instructionSearchRows(direct, reached *rvaBits, traces []valueTraceHit) iter.Seq[instructionSearchRow] {
	return func(yield func(instructionSearchRow) bool) {
		for _, confirmed := range []bool{true, false} {
			confidence := "candidate"
			if confirmed {
				confidence = "confirmed"
			}
			for rva := range direct.addresses {
				if reached.has(rva) == confirmed && !yield(instructionSearchRow{rva: rva, confidence: confidence}) {
					return
				}
			}
		}
		for _, h := range traces {
			confidence := "trace confirmed"
			if h.possible {
				confidence = "trace possible"
			}
			if !yield(instructionSearchRow{rva: h.rva, confidence: confidence, trace: h.text}) {
				return
			}
		}
	}
}

func renderInstructionSearch(input AnalyzeInput, spec instructionSearchSpec, bin *cgBinary, reached *rvaBits,
	traces []valueTraceHit, traceValues, complete bool) (string, error) {
	capacity := input.MaxOutputChars
	if capacity <= 0 {
		capacity = defaultAnalyzeOutputChars
	}
	if capacity < 256 {
		return "", fmt.Errorf("instruction_search max_output_chars must be at least 256")
	}
	directTotal := 0
	var heading strings.Builder
	if spec.matches != nil {
		directTotal = spec.matches.count()
		fmt.Fprintf(&heading, "Direct instruction matches: %d\n", directTotal)
	}
	if traceValues {
		fmt.Fprintf(&heading, "Value-flow findings: %d\n", len(traces))
	}
	heading.WriteString("Instruction search: " + formatInstructionFilter(spec))
	rows := instructionSearchRows(spec.matches, reached, traces)
	if input.GroupByFunction {
		groups := groupInstructionSearch(bin, rows)
		return instructionSearchPage(input, capacity, heading.String(), len(groups), complete, "functions",
			func(yield func(instructionSearchGroup) bool) {
				for _, group := range groups {
					if !yield(group) {
						return
					}
				}
			}, formatInstructionSearchGroup), nil
	}
	loc := &xrefLocator{imageBase: bin.imageBase, funcs: bin.funcTable, symbols: bin.symbols}
	mode := 32
	if bin.is64 {
		mode = 64
	}
	return instructionSearchPage(input, capacity, heading.String(), directTotal+len(traces), complete, "matches", rows,
		func(row instructionSearchRow) string {
			va := bin.imageBase + uint64(row.rva)
			label, _ := loc.function(va)
			if label != "" {
				label = "  ; in " + label
			}
			description := row.trace
			if description == "" {
				if sec := sectionContainingRVA(bin.execSections, row.rva); sec != nil {
					inst, err := x86asm.Decode(sec.data[row.rva-sec.rva:], mode)
					if err == nil {
						description = x86asm.IntelSyntax(inst, va, nil)
					}
				}
			}
			return fmt.Sprintf("  [%s] 0x%x: %s%s", row.confidence, va, description, label)
		}), nil
}

type instructionSearchGroup struct {
	va                  uint64
	name                string
	direct, trace       int
	candidate, possible int
}

func groupInstructionSearch(bin *cgBinary, rows iter.Seq[instructionSearchRow]) []instructionSearchGroup {
	byEntry := make(map[uint32]*instructionSearchGroup)
	unknown := &instructionSearchGroup{name: "outside known functions"}
	for row := range rows {
		group := unknown
		if f := findFunc(bin.funcTable, row.rva); f != nil {
			entry := f.entry()
			group = byEntry[entry]
			if group == nil {
				va := bin.imageBase + uint64(entry)
				name := bin.symbols[va]
				if name == "" {
					name = fmt.Sprintf("sub_%x", va)
				}
				group = &instructionSearchGroup{va: va, name: name}
				byEntry[entry] = group
			}
		}
		switch row.confidence {
		case "trace confirmed":
			group.trace++
		case "trace possible":
			group.trace++
			group.possible++
		case "candidate":
			group.direct++
			group.candidate++
		default:
			group.direct++
		}
	}
	groups := make([]instructionSearchGroup, 0, len(byEntry)+1)
	for _, group := range byEntry {
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if totalA, totalB := a.direct+a.trace, b.direct+b.trace; totalA != totalB {
			return totalA > totalB
		}
		return a.va < b.va
	})
	if unknown.direct+unknown.trace != 0 {
		groups = append(groups, *unknown)
	}
	return groups
}

func formatInstructionSearchGroup(g instructionSearchGroup) string {
	location := g.name
	if location != "outside known functions" {
		location = fmt.Sprintf("0x%x %s", g.va, location)
	}
	return fmt.Sprintf("  %s: %d matches (%d direct, %d trace; %d candidates, %d possible)", location,
		g.direct+g.trace, g.direct, g.trace, g.candidate, g.possible)
}

func instructionSearchPage[T any](input AnalyzeInput, capacity int, heading string, total int, complete bool, unit string,
	rows iter.Seq[T], format func(T) string) string {
	offset := min(max(0, input.ResultOffset), total)
	limit := total
	if input.MaxResults > 0 {
		limit = min(input.MaxResults, maxInstructionSearchResults)
	}
	footer := func(shown, next int) string {
		status := fmt.Sprintf("\nShown %d of %d %s (offset %d).", shown, total, unit, offset)
		if !complete {
			status += " Partial analysis: decode budget exhausted."
		}
		if next < total {
			status += fmt.Sprintf(" Continue with result_offset=%d.", next)
		}
		return status
	}
	reserve := utf8.RuneCountInString(footer(total, max(0, total-1)))
	heading, _ = common.TruncateRunes(heading, min(capacity/2, capacity-reserve-2), "…")
	var out strings.Builder
	out.WriteString(heading)
	out.WriteByte('\n')
	budget := capacity - reserve - utf8.RuneCountInString(heading) - 1
	shown := 0
	if offset < total {
		rowIndex := 0
		for row := range rows {
			if rowIndex < offset {
				rowIndex++
				continue
			}
			if shown == limit {
				break
			}
			line := format(row)
			size := utf8.RuneCountInString(line) + 1
			if size > budget {
				if shown != 0 {
					break
				}
				line, _ = common.TruncateRunes(line, budget-1, "…")
				size = utf8.RuneCountInString(line) + 1
			}
			out.WriteString(line)
			out.WriteByte('\n')
			budget -= size
			shown++
		}
	}
	out.WriteString(footer(shown, offset+shown))
	return out.String()
}
