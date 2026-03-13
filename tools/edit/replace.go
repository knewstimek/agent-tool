package edit

import (
	"fmt"
	"strings"
)

// ReplaceResult는 치환 결과를 담는다.
type ReplaceResult struct {
	Content    string
	MatchCount int
	Applied    bool
	Message    string
}

// Replace는 content에서 oldStr을 newStr로 치환한다.
// 파일의 들여쓰기 스타일에 맞게 자동 변환을 시도한다.
// forceStyle이 true이면 1차 직접 매칭에서도 newStr의 들여쓰기를 fileStyle로 강제 변환한다.
func Replace(content, oldStr, newStr string, replaceAll bool, fileStyle IndentStyle, forceStyle bool) ReplaceResult {
	// 줄바꿈 정규화: old_string의 \n을 파일의 줄바꿈에 맞게 변환
	lineEnding := "\n"
	if strings.Contains(content, "\r\n") {
		lineEnding = "\r\n"
	}

	// old_string/new_string의 줄바꿈을 파일과 일치시킴
	normalizedOld := normalizeLineEnding(oldStr, lineEnding)
	normalizedNew := normalizeLineEnding(newStr, lineEnding)

	// 1차: 원본 문자열로 직접 매칭
	count := strings.Count(content, normalizedOld)
	if count > 0 {
		finalNew := normalizedNew
		// forceStyle: 명시적 indent_style 지정 시 newStr도 fileStyle로 강제 변환
		if forceStyle {
			newStyle := DetectIndentOfString(newStr)
			if newStyle.UseTabs != fileStyle.UseTabs || newStyle.IndentSize != fileStyle.IndentSize {
				finalNew = ConvertIndent(normalizedNew, newStyle, fileStyle)
			}
		}
		return applyReplace(content, normalizedOld, finalNew, count, replaceAll)
	}

	// 2차: 들여쓰기 변환 후 매칭 (공백 → 탭 또는 탭 → 공백)
	srcStyle := DetectIndentOfString(oldStr)
	if srcStyle.UseTabs != fileStyle.UseTabs {
		convertedOld := ConvertIndent(normalizedOld, srcStyle, fileStyle)
		convertedNew := ConvertIndent(normalizedNew, srcStyle, fileStyle)

		count = strings.Count(content, convertedOld)
		if count > 0 {
			return applyReplace(content, convertedOld, convertedNew, count, replaceAll)
		}
	}

	// 3차: 파일이 탭인데 old_string에 공백이 있는 경우 강제 변환 시도
	if fileStyle.UseTabs && HasLeadingSpaces(normalizedOld) {
		convertedOld := SpacesToTabs(normalizedOld, fileStyle.IndentSize)
		convertedNew := SpacesToTabs(normalizedNew, fileStyle.IndentSize)

		count = strings.Count(content, convertedOld)
		if count > 0 {
			return applyReplace(content, convertedOld, convertedNew, count, replaceAll)
		}
	}

	return ReplaceResult{
		Applied: false,
		Message: "old_string not found in file",
	}
}

// applyReplace는 실제 치환을 수행한다.
// count > 1이고 replaceAll이 false이면 치환하지 않고 오류를 반환한다.
func applyReplace(content, oldStr, newStr string, count int, replaceAll bool) ReplaceResult {
	if !replaceAll && count > 1 {
		return ReplaceResult{
			Applied: false,
			Message: fmt.Sprintf("old_string found %d times. Use replace_all=true or provide more context to make it unique", count),
		}
	}

	var result string
	if replaceAll {
		result = strings.ReplaceAll(content, oldStr, newStr)
	} else {
		result = strings.Replace(content, oldStr, newStr, 1)
	}

	return ReplaceResult{
		Content:    result,
		MatchCount: count,
		Applied:    true,
		Message:    fmt.Sprintf("replaced %d occurrence(s)", count),
	}
}

func normalizeLineEnding(s, target string) string {
	// 먼저 모든 줄바꿈을 \n으로 통일
	s = strings.ReplaceAll(s, "\r\n", "\n")
	// 대상 줄바꿈으로 변환
	if target == "\r\n" {
		s = strings.ReplaceAll(s, "\n", "\r\n")
	}
	return s
}
