package common

import (
	"bufio"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestLongLineTruncationKeepsAllocationBounded(t *testing.T) {
	input := strings.Repeat("\uac00", 2*1024*1024)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got, cut := TruncateRunes(input, 4000, "…")
	runtime.ReadMemStats(&after)
	if !cut || utf8.RuneCountInString(got) != 4000 || !utf8.ValidString(got) {
		t.Fatal("invalid truncated prefix")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1024*1024 {
		t.Fatalf("short prefix allocated %d bytes", allocated)
	}
}

func TestTruncateRunesKeepsUTF8Valid(t *testing.T) {
	got, truncated := TruncateRunes("가나다라마바사", 5, "…")
	if !truncated || got != "가나다라…" {
		t.Fatalf("got %q truncated=%v", got, truncated)
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncation produced invalid UTF-8")
	}
}

func TestAppendWithinRuneBudgetIsAtomic(t *testing.T) {
	var sb strings.Builder
	used := 0
	if !AppendWithinRuneBudget(&sb, &used, "가나", 3) {
		t.Fatal("first fragment should fit")
	}
	if AppendWithinRuneBudget(&sb, &used, "다라", 3) {
		t.Fatal("second fragment should not fit")
	}
	if sb.String() != "가나" || used != 2 {
		t.Fatalf("partial fragment was appended: %q, used=%d", sb.String(), used)
	}
}

func TestEveryTextLineFormUsesSameBoundaries(t *testing.T) {
	for _, text := range []string{"", "a\r\nb\rc\n", "\r\n\r", "a\r", "a\r\nb"} {
		scanner := bufio.NewScanner(strings.NewReader(text))
		scanner.Buffer(make([]byte, 2), 1024)
		scanner.Split(ScanTextLines)
		var scanned []string
		for scanner.Scan() {
			scanned = append(scanned, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		lines := TextLines(text)
		if !reflect.DeepEqual(lines, scanned) && !(len(lines) == 0 && len(scanned) == 0) {
			t.Fatalf("%q: lines=%q scanned=%q", text, lines, scanned)
		}
		if TextLineCount(text) != len(scanned) {
			t.Fatalf("%q: count mismatch", text)
		}
	}
}

func TestTextLineCountMatchesScanLines(t *testing.T) {
	tests := map[string]int{
		"":           0,
		"one":        1,
		"one\n":      1,
		"one\ntwo":   2,
		"one\ntwo\n": 2,
		"one\n\n":    2,
	}
	for input, want := range tests {
		if got := TextLineCount(input); got != want {
			t.Errorf("TextLineCount(%q) = %d, want %d", input, got, want)
		}
	}
}

func TestLimitToolResultTextIsVisibleAndUTF8Safe(t *testing.T) {
	result := &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: strings.Repeat("가", 200)},
	}}
	if !LimitToolResultText(result, 120) {
		t.Fatal("expected truncation")
	}
	got := result.Content[0].(*mcp.TextContent).Text
	if !utf8.ValidString(got) {
		t.Fatal("result is not valid UTF-8")
	}
	if utf8.RuneCountInString(got) > 120 {
		t.Fatalf("result exceeds limit: %d", utf8.RuneCountInString(got))
	}
	if !strings.Contains(got, "truncated=true") || !strings.Contains(got, "original_chars=200") {
		t.Fatalf("missing actionable truncation metadata: %q", got)
	}
}
