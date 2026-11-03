package edit

import (
	"strings"

	"agent-tool/common"
)

// replaceUniqueIndentedLine recovers a single-line anchor whose body occurs
// exactly once. The actual line supplies its base indentation; a file-wide
// majority must not rewrite a minority space/tab region.
func replaceUniqueIndentedLine(m *common.LineEndingMap, oldText, newText string, fileStyle IndentStyle) (ReplaceResult, bool) {
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
	sourceBase := indentColumns(oldPrefix, sourceWidth)
	targetBase := indentColumns(actualPrefix, targetWidth)
	// Explicit mixed-prefix alignment is meaningful. Do not reinterpret a
	// dangling space after a tab as a different nesting depth.
	if strings.Contains(oldPrefix, "\t") && strings.Contains(oldPrefix, " ") &&
		sourceBase%sourceWidth != targetBase%targetWidth {
		return ReplaceResult{}, false
	}
	lines := strings.Split(newText, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
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
	actualOld := m.Norm[start:end]
	return applyLineStartReplace(m, actualOld, strings.Join(lines, "\n"), false), true
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
