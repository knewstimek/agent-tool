package common

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// DefaultOutputChars is the normal response budget for tools that can emit
	// user-controlled or data-dependent amounts of text.
	DefaultOutputChars = 32 * 1024
	// HardOutputChars is a final server-wide safety net. Individual tools should
	// normally use DefaultOutputChars and provide a useful continuation cursor.
	HardOutputChars = 128 * 1024
)

// ScanTextLines recognizes LF, CRLF and bare CR without phantom final lines.
func ScanTextLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		n := i + 1
		if data[i] == '\r' {
			if n == len(data) && !atEOF {
				return 0, nil, nil
			}
			if n < len(data) && data[n] == '\n' {
				n++
			}
		}
		return n, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// TextLineCount uses the same newline forms as ScanTextLines. A final
// terminator does not create a nonexistent continuation line.
func TextLineCount(text string) int {
	if text == "" {
		return 0
	}
	count := 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\r':
			count++
			if i+1 < len(text) && text[i+1] == '\n' {
				i++
			}
		case '\n':
			count++
		}
	}
	if last := text[len(text)-1]; last != '\r' && last != '\n' {
		count++
	}
	return count
}

// TextLines returns views of each logical line, without copying line bodies.
func TextLines(text string) []string {
	lines := make([]string, 0, TextLineCount(text))
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] != '\r' && text[i] != '\n' {
			continue
		}
		lines = append(lines, text[start:i])
		if text[i] == '\r' && i+1 < len(text) && text[i+1] == '\n' {
			i++
		}
		start = i + 1
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

// TruncateRunes limits text by Unicode code points rather than bytes so tool
// output never contains a broken UTF-8 sequence. The caller supplies the
// suffix because different tools need different continuation guidance.
func TruncateRunes(text string, maxRunes int, suffix string) (string, bool) {
	if maxRunes < 0 {
		return text, false
	}
	keep := maxRunes - utf8.RuneCountInString(suffix)
	if keep <= 0 {
		keep = maxRunes
		suffix = ""
	}
	prefixEnd, count := 0, 0
	// Visit only the output prefix, rather than allocating a rune slice for a
	// potentially multi-megabyte line that will be shortened to a few KB.
	for i := range text {
		if count == keep {
			prefixEnd = i
		}
		if count == maxRunes {
			prefix := text[:prefixEnd]
			if !utf8.ValidString(prefix) {
				prefix = strings.ToValidUTF8(prefix, "\ufffd")
			}
			return prefix + suffix, true
		}
		count++
	}
	return text, false
}

// AppendWithinRuneBudget appends text only when the complete fragment fits.
// Keeping result records atomic lets callers report an exact continuation
// offset instead of cutting a row, variable, or symbol in half.
func AppendWithinRuneBudget(sb *strings.Builder, used *int, text string, maxRunes int) bool {
	n := utf8.RuneCountInString(text)
	if maxRunes > 0 && *used+n > maxRunes {
		return false
	}
	sb.WriteString(text)
	*used += n
	return true
}

// LimitToolResultText applies the server-wide last-resort response cap to all
// text content in a tool result. Tool-specific pagination remains preferable:
// this guard exists so a newly-added or overlooked tool can never dump
// megabytes into an agent context without saying that data was omitted.
// Non-text content (for example MCP images) is left untouched.
func LimitToolResultText(result *mcp.CallToolResult, maxRunes int) bool {
	if result == nil || maxRunes <= 0 {
		return false
	}

	total := 0
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			total += utf8.RuneCountInString(text.Text)
		}
	}
	if total <= maxRunes {
		return false
	}

	suffix := fmt.Sprintf(
		"\n[truncated=true; original_chars=%d; limit=%d; narrow the request or use paging parameters]",
		total, maxRunes,
	)
	remaining := maxRunes
	markerWritten := false
	filtered := make([]mcp.Content, 0, len(result.Content))
	for _, content := range result.Content {
		text, ok := content.(*mcp.TextContent)
		if !ok {
			filtered = append(filtered, content)
			continue
		}
		if markerWritten {
			continue
		}

		count := utf8.RuneCountInString(text.Text)
		if count < remaining-utf8.RuneCountInString(suffix) {
			filtered = append(filtered, text)
			remaining -= count
			continue
		}

		limited, _ := TruncateRunes(text.Text, remaining, suffix)
		copyText := *text
		copyText.Text = limited
		filtered = append(filtered, &copyText)
		markerWritten = true
	}
	result.Content = filtered
	return true
}
