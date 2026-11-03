package edit

import (
	"bufio"
	"iter"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// IndentStyle represents the indentation style of a file.
type IndentStyle struct {
	UseTabs    bool
	IndentSize int // tab width or number of spaces (2, 4, etc.)
}

// EditorConfigResult holds the full settings read from .editorconfig.
type EditorConfigResult struct {
	Indent  *IndentStyle
	Charset string // "utf-8", "euc-kr", "latin1", etc. Empty string means unspecified.
}

var (
	reLeadingSpaces = regexp.MustCompile(`^  +\S`)
	reSectionHeader = regexp.MustCompile(`^\[(.+)\]`)
)

// DetectIndent detects the indentation style from file content.
// Checks .editorconfig first, falls back to content-based detection.
func DetectIndent(filePath string, content string) IndentStyle {
	// 1. Check .editorconfig
	if ec := findEditorConfig(filePath); ec != nil {
		// Preserve the content style when space indentation predominates over
		// a conflicting tab setting.
		if ec.UseTabs && !detectTabsFromContent(content) && hasSpaceIndentation(content) {
			return detectIndentFromContent(content)
		}
		return *ec
	}

	// 2. Content-based detection
	return detectIndentFromContent(content)
}

// DetectIndentOfString detects the indentation style of the string itself.
func DetectIndentOfString(s string) IndentStyle {
	return detectIndentFromContent(s)
}

// SpacesToTabs converts leading spaces to tabs on each line.
func SpacesToTabs(text string, indentSize int) string {
	if indentSize <= 0 {
		indentSize = 4
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if len(line) == 0 || line[0] != ' ' {
			continue
		}

		stripped := strings.TrimLeft(line, " ")
		nSpaces := len(line) - len(stripped)

		// A single space is likely alignment, not indentation — skip conversion
		if nSpaces < 2 {
			continue
		}

		nTabs := nSpaces / indentSize
		remaining := nSpaces % indentSize
		lines[i] = strings.Repeat("\t", nTabs) + strings.Repeat(" ", remaining) + stripped
	}
	return strings.Join(lines, "\n")
}

// TabsToSpaces converts leading tabs to spaces on each line.
func TabsToSpaces(text string, indentSize int) string {
	if indentSize <= 0 {
		indentSize = 4
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if len(line) == 0 || line[0] != '\t' {
			continue
		}

		stripped := strings.TrimLeft(line, "\t")
		nTabs := len(line) - len(stripped)
		lines[i] = strings.Repeat(" ", nTabs*indentSize) + stripped
	}
	return strings.Join(lines, "\n")
}

// ConvertIndent converts text from src style to dst style.
// Handles tab-space conversion as well as space size conversion (e.g. 2->4, 4->2).
func ConvertIndent(text string, src, dst IndentStyle) string {
	if src.UseTabs == dst.UseTabs && src.IndentSize == dst.IndentSize {
		return text
	}
	if src.UseTabs && !dst.UseTabs {
		// Tabs -> spaces
		return TabsToSpaces(text, dst.IndentSize)
	}
	if !src.UseTabs && dst.UseTabs {
		// Spaces -> tabs
		return SpacesToTabs(text, src.IndentSize)
	}
	// Spaces -> spaces (size conversion: e.g. 2-space -> 4-space)
	if src.IndentSize != dst.IndentSize && src.IndentSize > 0 {
		return RescaleSpaces(text, src.IndentSize, dst.IndentSize)
	}
	return text
}

// RescaleSpaces rescales leading spaces.
// e.g. srcSize=2, dstSize=4 converts 2 spaces to 4 spaces (preserving indent level).
func RescaleSpaces(text string, srcSize, dstSize int) string {
	if srcSize <= 0 || dstSize <= 0 || srcSize == dstSize {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if len(line) == 0 || line[0] != ' ' {
			continue
		}
		stripped := strings.TrimLeft(line, " ")
		nSpaces := len(line) - len(stripped)
		// Calculate indent level and convert to new size
		level := nSpaces / srcSize
		remainder := nSpaces % srcSize
		newSpaces := level*dstSize + remainder
		lines[i] = strings.Repeat(" ", newSpaces) + stripped
	}
	return strings.Join(lines, "\n")
}

// HasLeadingSpaces checks whether the text has space indentation.
func HasLeadingSpaces(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if reLeadingSpaces.MatchString(line) {
			return true
		}
	}
	return false
}

// indentLines samples up to 8 MiB without a line-count or Scanner token
// limit. CR, LF and CRLF files use the same detection path.
func indentLines(content string) iter.Seq[string] {
	return func(yield func(string) bool) {
		if len(content) > 8*1024*1024 {
			content = content[:8*1024*1024]
			// Exclude a partial final line.
			if end := strings.LastIndexAny(content, "\r\n"); end >= 0 {
				content = content[:end]
			} else {
				return
			}
		}
		for content != "" {
			end := strings.IndexAny(content, "\r\n")
			if end < 0 {
				yield(content)
				return
			}
			line := content[:end]
			next := end + 1
			if content[end] == '\r' && next < len(content) && content[next] == '\n' {
				next++
			}
			content = content[next:]
			if !yield(line) {
				return
			}
		}
	}
}

// detectIndentFromContent estimates the indentation style from a bounded sample.
// Uses tabs if tab lines >= space lines; otherwise estimates indentSize from space diffs between consecutive lines.
func detectIndentFromContent(content string) IndentStyle {
	tabLines := 0
	spaceLines := 0
	spaceDiffs := make(map[int]int) // indent depth difference frequency

	prevSpaces := 0
	for line := range indentLines(content) {

		if strings.TrimSpace(line) == "" {
			continue
		}

		if line[0] == '\t' {
			tabLines++
		} else if line[0] == ' ' && reLeadingSpaces.MatchString(line) {
			spaceLines++
			nSpaces := len(line) - len(strings.TrimLeft(line, " "))
			// Both indentation and dedentation reveal the unit. Large changes
			// are more likely alignment or skipped nesting levels.
			diff := nSpaces - prevSpaces
			if diff < 0 {
				diff = -diff
			}
			if diff > 0 && diff <= 8 {
				spaceDiffs[diff]++
			}
			prevSpaces = nSpaces
		} else {
			prevSpaces = 0
		}
	}

	if tabLines > 0 && tabLines >= spaceLines {
		return IndentStyle{UseTabs: true, IndentSize: 4}
	}

	// Estimate space indentation size
	indentSize := 4
	maxCount := 0
	for size, count := range spaceDiffs {
		if count > maxCount || count == maxCount && size < indentSize {
			maxCount = count
			indentSize = size
		}
	}

	return IndentStyle{UseTabs: false, IndentSize: indentSize}
}

// detectTabsFromContent returns whether tab-indented lines outnumber space-indented lines.
// Used by DetectIndent to verify consistency between .editorconfig and actual file content.
func detectTabsFromContent(content string) bool {
	tabLines := 0
	spaceLines := 0

	for line := range indentLines(content) {

		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] == '\t' {
			tabLines++
		} else if reLeadingSpaces.MatchString(line) {
			spaceLines++
		}
	}

	return tabLines > 0 && tabLines > spaceLines
}

// hasSpaceIndentation returns whether at least one line with space indentation exists.
// Unlike detectTabsFromContent, checks only for existence rather than ratio.
func hasSpaceIndentation(content string) bool {
	for line := range indentLines(content) {
		if reLeadingSpaces.MatchString(line) {
			return true
		}
	}
	return false
}

// --- .editorconfig parsing ---

// FindEditorConfigCharset finds the charset setting from .editorconfig.
// Empty string means charset is not specified.
func FindEditorConfigCharset(filePath string) string {
	ec := findEditorConfigFull(filePath)
	if ec == nil {
		return ""
	}
	return ec.Charset
}

func findEditorConfig(filePath string) *IndentStyle {
	ec := findEditorConfigFull(filePath)
	if ec == nil {
		return nil
	}
	return ec.Indent
}

func findEditorConfigFull(filePath string) *EditorConfigResult {
	dir := filepath.Dir(filePath)
	props := make(map[string]string)
	for {
		local, root := readEditorConfigProps(filepath.Join(dir, ".editorconfig"), filePath)
		// Walk nearest first, inheriting only properties not specified below.
		// Keep "unset" until after merging so it blocks inheritance too.
		for key, value := range local {
			if _, exists := props[key]; !exists {
				props[key] = value
			}
		}
		if root {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	for key, value := range props {
		if value == "unset" {
			delete(props, key)
		}
	}
	return editorConfigResult(props)
}

// readEditorConfigProps returns matching properties and the preamble's root flag.
// filePath must be an absolute path.
func readEditorConfigProps(ecPath, filePath string) (map[string]string, bool) {
	f, err := os.Open(ecPath)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	filename := filepath.Base(filePath)
	ecDir := filepath.Dir(ecPath)

	scanner := bufio.NewScanner(f)
	props := make(map[string]string)
	inMatchingSection := false
	inSection := false
	root := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		if m := reSectionHeader.FindStringSubmatch(line); m != nil {
			inSection = true
			pattern := m[1]
			patterns := expandBraces(pattern)
			inMatchingSection = false
			for _, p := range patterns {
				var matched bool
				if strings.Contains(p, "/") {
					// Pattern with path: match using relative path from .editorconfig location
					relPath, relErr := filepath.Rel(ecDir, filePath)
					if relErr == nil {
						matched, _ = filepath.Match(p, filepath.ToSlash(relPath))
					}
				} else {
					matched, _ = filepath.Match(p, filename)
				}
				if matched {
					inMatchingSection = true
					break
				}
			}
			continue
		}

		if idx := strings.Index(line, "="); idx >= 0 {
			key := strings.TrimSpace(strings.ToLower(line[:idx]))
			val := strings.TrimSpace(strings.ToLower(line[idx+1:]))
			if !inSection && key == "root" {
				root = val == "true"
			} else if inMatchingSection {
				props[key] = val
			}
		}
	}
	return props, root
}

func editorConfigResult(props map[string]string) *EditorConfigResult {
	// Return result if at least one of indent or charset is found
	var indent *IndentStyle
	if props["indent_style"] == "tab" {
		size := 4
		if v, ok := props["indent_size"]; ok {
			if n := parseInt(v); n > 0 {
				size = n
			}
		}
		indent = &IndentStyle{UseTabs: true, IndentSize: size}
	} else if props["indent_style"] == "space" {
		size := 4
		if v, ok := props["indent_size"]; ok {
			if n := parseInt(v); n > 0 {
				size = n
			}
		}
		indent = &IndentStyle{UseTabs: false, IndentSize: size}
	}

	charset := props["charset"] // "utf-8", "euc-kr", "latin1", "utf-8-bom", etc.

	if indent == nil && charset == "" {
		return nil
	}

	return &EditorConfigResult{
		Indent:  indent,
		Charset: charset,
	}
}

func expandBraces(pattern string) []string {
	start := strings.Index(pattern, "{")
	if start < 0 {
		return []string{pattern}
	}
	end := strings.Index(pattern[start:], "}")
	if end < 0 {
		return []string{pattern}
	}
	end += start // convert from pattern[start:] relative to absolute index

	prefix := pattern[:start]
	suffix := pattern[end+1:]
	options := strings.Split(pattern[start+1:end], ",")

	var result []string
	for _, opt := range options {
		expanded := expandBraces(prefix + strings.TrimSpace(opt) + suffix)
		result = append(result, expanded...)
	}
	return result
}

// parseInt parses only the leading consecutive digits of a string.
// Unlike strconv.Atoi, it stops at non-digit characters without error,
// naturally ignoring .editorconfig inline comments like "4  # comment".
func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
		if n > 1000 {
			return n // overflow prevention: reasonable upper bound for indent_size
		}
	}
	return n
}
