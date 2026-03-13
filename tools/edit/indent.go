package edit

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// IndentStyle은 파일의 들여쓰기 스타일을 나타낸다.
type IndentStyle struct {
	UseTabs    bool
	IndentSize int // 탭 너비 또는 공백 수 (2, 4 등)
}

// EditorConfigResult는 .editorconfig에서 읽은 전체 설정을 담는다.
type EditorConfigResult struct {
	Indent  *IndentStyle
	Charset string // "utf-8", "euc-kr", "latin1" 등. 빈 문자열이면 미지정.
}

var (
	reLeadingSpaces = regexp.MustCompile(`^  +\S`)
	reSectionHeader = regexp.MustCompile(`^\[(.+)\]`)
	reRootTrue      = regexp.MustCompile(`(?i)^\s*root\s*=\s*true`)
)

// DetectIndent는 파일 내용에서 들여쓰기 스타일을 감지한다.
// .editorconfig를 우선 확인하고, 없으면 파일 내용 기반으로 판단한다.
func DetectIndent(filePath string, content string) IndentStyle {
	// 1. .editorconfig 확인
	if ec := findEditorConfig(filePath); ec != nil {
		// 레거시 보호: .editorconfig가 탭이어도 실제 파일이 공백이면 변환 안 함
		if ec.UseTabs && !detectTabsFromContent(content) && hasSpaceIndentation(content) {
			return IndentStyle{UseTabs: false, IndentSize: ec.IndentSize}
		}
		return *ec
	}

	// 2. 파일 내용 기반 감지
	return detectIndentFromContent(content)
}

// DetectIndentOfString은 문자열 자체의 들여쓰기 스타일을 감지한다.
func DetectIndentOfString(s string) IndentStyle {
	return detectIndentFromContent(s)
}

// SpacesToTabs는 각 줄의 선행 공백을 탭으로 변환한다.
func SpacesToTabs(text string, indentSize int) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if len(line) == 0 || line[0] != ' ' {
			continue
		}

		stripped := strings.TrimLeft(line, " ")
		nSpaces := len(line) - len(stripped)

		if nSpaces < 2 {
			continue
		}

		nTabs := nSpaces / indentSize
		remaining := nSpaces % indentSize
		lines[i] = strings.Repeat("\t", nTabs) + strings.Repeat(" ", remaining) + stripped
	}
	return strings.Join(lines, "\n")
}

// TabsToSpaces는 각 줄의 선행 탭을 공백으로 변환한다.
func TabsToSpaces(text string, indentSize int) string {
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

// ConvertIndent는 src 스타일의 텍스트를 dst 스타일로 변환한다.
func ConvertIndent(text string, src, dst IndentStyle) string {
	if src.UseTabs == dst.UseTabs {
		return text
	}
	if src.UseTabs && !dst.UseTabs {
		return TabsToSpaces(text, dst.IndentSize)
	}
	return SpacesToTabs(text, src.IndentSize)
}

// HasLeadingSpaces는 텍스트에 공백 들여쓰기가 있는지 확인한다.
func HasLeadingSpaces(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if reLeadingSpaces.MatchString(line) {
			return true
		}
	}
	return false
}

func detectIndentFromContent(content string) IndentStyle {
	scanner := bufio.NewScanner(strings.NewReader(content))
	tabLines := 0
	spaceLines := 0
	lineCount := 0
	spaceDiffs := make(map[int]int) // 들여쓰기 깊이 차이 빈도

	prevSpaces := 0
	for scanner.Scan() {
		if lineCount >= 100 {
			break
		}
		line := scanner.Text()
		lineCount++

		if len(line) == 0 {
			continue
		}

		if line[0] == '\t' {
			tabLines++
		} else if line[0] == ' ' && reLeadingSpaces.MatchString(line) {
			spaceLines++
			nSpaces := len(line) - len(strings.TrimLeft(line, " "))
			if diff := nSpaces - prevSpaces; diff > 0 && diff <= 8 {
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

	// 공백 들여쓰기의 크기 추정
	indentSize := 4
	maxCount := 0
	for size, count := range spaceDiffs {
		if count > maxCount {
			maxCount = count
			indentSize = size
		}
	}

	return IndentStyle{UseTabs: false, IndentSize: indentSize}
}

func detectTabsFromContent(content string) bool {
	scanner := bufio.NewScanner(strings.NewReader(content))
	tabLines := 0
	spaceLines := 0
	lineCount := 0

	for scanner.Scan() {
		if lineCount >= 100 {
			break
		}
		line := scanner.Text()
		lineCount++

		if len(line) == 0 {
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

func hasSpaceIndentation(content string) bool {
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineCount := 0
	for scanner.Scan() {
		if lineCount >= 100 {
			break
		}
		if reLeadingSpaces.MatchString(scanner.Text()) {
			return true
		}
		lineCount++
	}
	return false
}

// --- .editorconfig 파싱 ---

// FindEditorConfigCharset는 .editorconfig에서 charset 설정을 찾는다.
// 빈 문자열이면 charset 미지정.
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
	filename := filepath.Base(filePath)

	for {
		ecPath := filepath.Join(dir, ".editorconfig")
		if _, err := os.Stat(ecPath); err == nil {
			if result := parseEditorConfig(ecPath, filename); result != nil {
				return result
			}
			// root = true이면 상위 탐색 중단
			if isRootEditorConfig(ecPath) {
				break
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}

func parseEditorConfig(ecPath, filename string) *EditorConfigResult {
	f, err := os.Open(ecPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	props := make(map[string]string)
	inMatchingSection := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		if m := reSectionHeader.FindStringSubmatch(line); m != nil {
			pattern := m[1]
			patterns := expandBraces(pattern)
			inMatchingSection = false
			for _, p := range patterns {
				matched, _ := filepath.Match(p, filename)
				if matched {
					inMatchingSection = true
					break
				}
			}
			continue
		}

		if inMatchingSection {
			if idx := strings.Index(line, "="); idx >= 0 {
				key := strings.TrimSpace(strings.ToLower(line[:idx]))
				val := strings.TrimSpace(strings.ToLower(line[idx+1:]))
				props[key] = val
			}
		}
	}

	// indent와 charset 중 하나라도 있으면 결과 반환
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

	charset := props["charset"] // "utf-8", "euc-kr", "latin1", "utf-8-bom" 등

	if indent == nil && charset == "" {
		return nil
	}

	return &EditorConfigResult{
		Indent:  indent,
		Charset: charset,
	}
}

func isRootEditorConfig(ecPath string) bool {
	data, err := os.ReadFile(ecPath)
	if err != nil {
		return false
	}
	return reRootTrue.Match(data)
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
	end += start

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

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
