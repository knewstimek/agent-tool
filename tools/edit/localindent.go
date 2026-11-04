package edit

import (
	"sort"
	"strings"

	"agent-tool/common"
)

// replaceUniqueIndentedLine recovers a single-line anchor whose body occurs
// exactly once. The actual line supplies its base indentation; a file-wide
// majority must not rewrite a minority space/tab region.
func replaceUniqueIndentedLine(m *common.LineEndingMap, oldText, newText string, fileStyle IndentStyle, analysis *indentAnalysis) (ReplaceResult, bool) {
	if !hasLeadingWhitespace(oldText) || strings.Contains(oldText, "\n") {
		return ReplaceResult{}, false
	}
	body := strings.TrimLeft(oldText, " \t")
	if body == "" || strings.Count(m.Norm, body) != 1 {
		return ReplaceResult{}, false
	}
	pos := strings.Index(m.Norm, body)
	start := strings.LastIndexByte(m.Norm[:pos], '\n') + 1
	end := pos + len(body)
	actualPrefix := m.Norm[start:pos]
	if strings.Trim(actualPrefix, " \t") != "" || end < len(m.Norm) && m.Norm[end] != '\n' {
		return ReplaceResult{}, false
	}
	oldPrefix := oldText[:len(oldText)-len(body)]
	sourceWidth := fileStyle.IndentSize
	if sourceWidth <= 0 {
		sourceWidth = 4
	}
	// A shallow 2/3-space anchor gives a smaller unit than the file's tab
	// width. A deep 8-space anchor alone is not evidence of an 8-space unit.
	if !strings.Contains(oldPrefix, "\t") && len(oldPrefix) < sourceWidth {
		sourceWidth = len(oldPrefix)
	}
	targetWidth := fileStyle.IndentSize
	if targetWidth <= 0 {
		targetWidth = 4
	}
	useTabs := strings.Contains(actualPrefix, "\t")
	if !useTabs && len(actualPrefix) > 0 && len(actualPrefix) < targetWidth {
		targetWidth = len(actualPrefix)
	}
	if !strings.Contains(oldPrefix, "\t") {
		if width, ok := structuralIndentWidth(newText, -1); ok {
			sourceWidth = width
		}
	}
	if !useTabs {
		targetWidth = analysis.width(m.Norm, start, targetWidth)
	}
	sourceBase := indentColumns(oldPrefix, sourceWidth)
	targetBase := indentColumns(actualPrefix, targetWidth)
	// Explicit mixed-prefix alignment is meaningful. Do not reinterpret a
	// dangling space after a tab as a different nesting depth.
	if strings.Contains(oldPrefix, "\t") && strings.Contains(oldPrefix, " ") &&
		sourceBase%sourceWidth != targetBase%targetWidth {
		return ReplaceResult{}, false
	}
	actualOld := m.Norm[start:end]
	return applyLineStartReplace(m, actualOld, analysis.rebase(newText, oldPrefix, actualPrefix, sourceWidth, targetWidth, useTabs), false), true
}

func rebaseIndent(newText, oldPrefix, actualPrefix string, sourceWidth, targetWidth int, useTabs bool) string {
	sourceBase := indentColumns(oldPrefix, sourceWidth)
	targetBase := indentColumns(actualPrefix, targetWidth)
	lines := strings.Split(newText, "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		tail := strings.TrimLeft(line, " \t")
		prefix := line[:len(line)-len(tail)]
		delta := indentColumns(prefix, sourceWidth) - sourceBase
		// Rescale levels but retain alignment spaces within a level.
		target := targetBase + delta/sourceWidth*targetWidth + delta%sourceWidth
		if target < 0 {
			target = 0
		}
		var corrected string
		switch {
		case target == targetBase:
			corrected = actualPrefix
		case useTabs:
			corrected = strings.Repeat("\t", target/targetWidth) + strings.Repeat(" ", target%targetWidth)
		default:
			corrected = strings.Repeat(" ", target)
		}
		lines[i] = corrected + tail
	}
	return strings.Join(lines, "\n")
}

// replaceUniqueIndentedBlock compares complete line bodies and their relative
// nesting. A different indentation style alone must not make a unique block
// uneditable; a different nesting shape must not be silently corrected.
func replaceUniqueIndentedBlock(m *common.LineEndingMap, oldText, newText string, replaceAll bool, fileStyle IndentStyle, analysis *indentAnalysis) (ReplaceResult, bool) {
	if !strings.Contains(oldText, "\n") {
		return ReplaceResult{}, false
	}
	trailing := strings.HasSuffix(oldText, "\n")
	oldLines := strings.Split(strings.TrimSuffix(oldText, "\n"), "\n")
	firstBody := strings.TrimLeft(oldLines[0], " \t")
	if firstBody == "" {
		return ReplaceResult{}, false
	}
	sourceStyle := DetectIndentOfString(oldText)
	sourceWidth := sourceStyle.IndentSize
	oldBasePrefix := oldLines[0][:len(oldLines[0])-len(firstBody)]
	oldBase := indentColumns(oldBasePrefix, sourceWidth)
	foundStart, foundEnd := -1, 0
	var corrected string
	prefixes := make([]string, 0, len(oldLines))
	for search := 0; search < len(m.Norm); {
		rel := strings.Index(m.Norm[search:], firstBody)
		if rel < 0 {
			break
		}
		pos := search + rel
		search = pos + len(firstBody)
		start := strings.LastIndexByte(m.Norm[:pos], '\n') + 1
		if strings.Trim(m.Norm[start:pos], " \t") != "" {
			continue
		}
		cursor := start
		prefixes = prefixes[:0]
		end := start
		matches := true
		for n, oldLine := range oldLines {
			if cursor >= len(m.Norm) {
				matches = false
				break
			}
			lineEnd := strings.IndexByte(m.Norm[cursor:], '\n')
			if lineEnd < 0 {
				lineEnd = len(m.Norm)
			} else {
				lineEnd += cursor
			}
			line := m.Norm[cursor:lineEnd]
			body := strings.TrimLeft(line, " \t")
			if body != strings.TrimLeft(oldLine, " \t") {
				matches = false
				break
			}
			prefixes = append(prefixes, line[:len(line)-len(body)])
			end = lineEnd
			if n < len(oldLines)-1 || trailing {
				if lineEnd == len(m.Norm) {
					matches = false
					break
				}
				end++
			}
			cursor = lineEnd + 1
		}
		if !matches {
			continue
		}
		actualStyle := DetectIndentOfString(m.Norm[start:end])
		targetWidth := actualStyle.IndentSize
		if !actualStyle.UseTabs {
			targetWidth = analysis.width(m.Norm, start, targetWidth)
		}
		for _, prefix := range prefixes {
			if strings.Contains(prefix, "\t") {
				targetWidth = 4
				if fileStyle.UseTabs && fileStyle.IndentSize > 0 {
					targetWidth = fileStyle.IndentSize
				}
				break
			}
		}
		mapped, mappedAll := mapBlockIndent(oldLines, prefixes, newText, newText, sourceWidth, targetWidth)
		actualBase := indentColumns(prefixes[0], targetWidth)
		for n, oldLine := range oldLines {
			if mappedAll {
				break
			}
			if strings.TrimSpace(oldLine) == "" {
				continue
			}
			oldPrefix := oldLine[:len(oldLine)-len(strings.TrimLeft(oldLine, " \t"))]
			delta := indentColumns(oldPrefix, sourceWidth) - oldBase
			wanted := delta/sourceWidth*targetWidth + delta%sourceWidth
			if indentColumns(prefixes[n], targetWidth)-actualBase != wanted {
				matches = false
				break
			}
			if strings.Contains(oldPrefix, "\t") && strings.Contains(oldPrefix, " ") &&
				indentColumns(oldPrefix, sourceWidth)%sourceWidth != indentColumns(prefixes[n], targetWidth)%targetWidth {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		if foundStart >= 0 {
			if replaceAll && m.Norm[foundStart:foundEnd] == m.Norm[start:end] {
				continue
			}
			return ReplaceResult{}, false
		}
		foundStart, foundEnd = start, end
		if mappedAll {
			corrected = mapped
		} else {
			corrected = rebaseIndent(newText, oldBasePrefix, prefixes[0], sourceWidth, targetWidth, actualStyle.UseTabs)
			corrected, _ = mapBlockIndent(oldLines, prefixes, newText, corrected, sourceWidth, targetWidth)
		}
		corrected = analysis.preserveSyntax(newText, corrected, sourceWidth, targetWidth, actualStyle.UseTabs)
	}
	if foundStart < 0 {
		return ReplaceResult{}, false
	}
	return applyLineStartReplace(m, m.Norm[foundStart:foundEnd], corrected, replaceAll), true
}

// A unique block supplies an exact mapping between existing indent prefixes.
// Reuse it for known levels, including alignment and indented blank lines;
// numeric unit inference is needed only for genuinely new levels. The ordering
// and equality of nesting levels must agree before any mapping is accepted.
func mapBlockIndent(oldLines, actualPrefixes []string, newText, fallback string, sourceWidth, targetWidth int) (string, bool) {
	prefixes := make([]string, len(oldLines))
	mapping := make(map[string]string)
	columns := make(map[int]int)
	for i, line := range oldLines {
		prefix := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		prefixes[i] = prefix
		if _, ok := mapping[prefix]; !ok {
			mapping[prefix] = actualPrefixes[i]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		source, target := indentColumns(prefix, sourceWidth), indentColumns(actualPrefixes[i], targetWidth)
		if prior, ok := columns[source]; ok && prior != target {
			return fallback, false
		}
		columns[source] = target
	}
	levels := make([]int, 0, len(columns))
	for level := range columns {
		levels = append(levels, level)
	}
	sort.Ints(levels)
	for i := 1; i < len(levels); i++ {
		if columns[levels[i]] <= columns[levels[i-1]] {
			return fallback, false
		}
	}
	input, output := strings.Split(newText, "\n"), strings.Split(fallback, "\n")
	all := true
	for i, line := range input {
		if line == "" {
			continue
		}
		body := strings.TrimLeft(line, " \t")
		prefix := line[:len(line)-len(body)]
		actual, ok := mapping[prefix]
		if i < len(prefixes) && prefixes[i] == prefix {
			actual, ok = actualPrefixes[i], true
		}
		if !ok {
			all = false
			continue
		}
		output[i] = actual + body
	}
	return strings.Join(output, "\n"), all
}

func indentColumns(prefix string, tabWidth int) int {
	columns := 0
	for _, c := range prefix {
		if c == '\t' {
			columns += tabWidth - columns%tabWidth
		} else {
			columns++
		}
	}
	return columns
}
