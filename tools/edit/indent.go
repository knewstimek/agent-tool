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
		// 레거시 보호: .editorconfig는 탭이지만, 실제 파일에 탭 줄이 없고
		// 공백 들여쓰기가 존재하면 → 파일의 기존 공백 스타일을 유지한다.
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

		// 공백 1개는 들여쓰기가 아닌 정렬(alignment)일 가능성이 높으므로 변환 안 함
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

// ConvertIndent는 src 스타일의 텍스트를 dst 스타일로 변환한다.
// 탭↔공백 변환뿐 아니라 공백 크기 변환(2→4, 4→2 등)도 처리한다.
func ConvertIndent(text string, src, dst IndentStyle) string {
	if src.UseTabs == dst.UseTabs && src.IndentSize == dst.IndentSize {
		return text
	}
	if src.UseTabs && !dst.UseTabs {
		// 탭 → 공백
		return TabsToSpaces(text, dst.IndentSize)
	}
	if !src.UseTabs && dst.UseTabs {
		// 공백 → 탭
		return SpacesToTabs(text, src.IndentSize)
	}
	// 공백 → 공백 (크기 변환: 예 2칸→4칸)
	if src.IndentSize != dst.IndentSize && src.IndentSize > 0 {
		return RescaleSpaces(text, src.IndentSize, dst.IndentSize)
	}
	return text
}

// RescaleSpaces는 선행 공백의 크기를 변환한다.
// 예: srcSize=2, dstSize=4이면 공백 2개를 공백 4개로 변환 (들여쓰기 레벨 유지).
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
		// 들여쓰기 레벨 계산 후 새 크기로 변환
		level := nSpaces / srcSize
		remainder := nSpaces % srcSize
		newSpaces := level*dstSize + remainder
		lines[i] = strings.Repeat(" ", newSpaces) + stripped
	}
	return strings.Join(lines, "\n")
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

// detectIndentFromContent는 최대 100줄을 스캔해 들여쓰기 스타일을 추정한다.
// 탭 줄이 공백 줄 이상이면 탭, 아니면 연속 줄 간 공백 차이로 indentSize를 추정한다.
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
			// 유효 들여쓰기 단위: 1~8. 9 이상은 정렬(alignment)일 가능성이 높아 제외한다.
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

// detectTabsFromContent는 탭 들여쓰기 줄이 공백 줄보다 많은지 반환한다.
// DetectIndent에서 .editorconfig 결과와 실제 파일의 일치 여부 확인에 사용된다.
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

// hasSpaceIndentation는 공백 들여쓰기가 1줄이라도 존재하는지 반환한다.
// detectTabsFromContent와 달리 비율이 아닌 존재 여부만 판단한다.
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

	for {
		ecPath := filepath.Join(dir, ".editorconfig")
		if _, err := os.Stat(ecPath); err == nil {
			if result := parseEditorConfig(ecPath, filePath); result != nil {
				return result
			}
			// 설정이 없는(result==nil) .editorconfig도 root=true이면 상위 탐색 중단
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

// parseEditorConfig는 .editorconfig 파일에서 filePath에 매칭되는 설정을 추출한다.
// filePath는 절대 경로여야 한다.
func parseEditorConfig(ecPath, filePath string) *EditorConfigResult {
	f, err := os.Open(ecPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	filename := filepath.Base(filePath)
	ecDir := filepath.Dir(ecPath)

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
				var matched bool
				if strings.Contains(p, "/") {
					// 경로 포함 패턴: .editorconfig 위치 기준 상대 경로로 매칭
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
	end += start // pattern[start:] 기준 → 전체 기준 절대 인덱스로 변환

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

// parseInt는 문자열 앞부분의 연속된 숫자만 파싱한다.
// strconv.Atoi와 달리 비숫자 문자에서 에러 없이 멈추므로,
// "4  # comment" 같은 .editorconfig 인라인 주석을 자연스럽게 무시한다.
func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
		if n > 1000 {
			return n // 오버플로우 방지: indent_size에 합리적인 상한
		}
	}
	return n
}
