package edit

import "testing"

func TestReplace_DirectMatch(t *testing.T) {
	content := "func main() {\n\tfmt.Println(\"hello\")\n}"
	result := Replace(content, "\"hello\"", "\"world\"", false, IndentStyle{UseTabs: true, IndentSize: 4}, false)

	if !result.Applied {
		t.Fatalf("expected match, got: %s", result.Message)
	}
	if result.MatchCount != 1 {
		t.Errorf("match count = %d, want 1", result.MatchCount)
	}
	want := "func main() {\n\tfmt.Println(\"world\")\n}"
	if result.Content != want {
		t.Errorf("got %q, want %q", result.Content, want)
	}
}

func TestReplace_SpacesToTabsConversion(t *testing.T) {
	// File uses tab indentation
	content := "func main() {\n\tfmt.Println(\"hello\")\n}"
	// LLM sends with spaces
	oldStr := "    fmt.Println(\"hello\")"
	newStr := "    fmt.Println(\"world\")"

	result := Replace(content, oldStr, newStr, false, IndentStyle{UseTabs: true, IndentSize: 4}, false)

	if !result.Applied {
		t.Fatalf("expected match after indent conversion, got: %s", result.Message)
	}
	want := "func main() {\n\tfmt.Println(\"world\")\n}"
	if result.Content != want {
		t.Errorf("got %q, want %q", result.Content, want)
	}
}

func TestReplace_NotFound(t *testing.T) {
	content := "func main() {}"
	result := Replace(content, "nonexistent", "replacement", false, IndentStyle{UseTabs: false, IndentSize: 4}, false)

	if result.Applied {
		t.Error("expected no match")
	}
	if result.Message != "old_string not found in file" {
		t.Errorf("unexpected message: %s", result.Message)
	}
}

func TestReplace_MultipleMatches_NoReplaceAll(t *testing.T) {
	content := "a = 1\nb = 1\nc = 1"
	result := Replace(content, "1", "2", false, IndentStyle{UseTabs: false, IndentSize: 4}, false)

	if result.Applied {
		t.Error("should fail with multiple matches when replace_all=false")
	}
}

func TestReplace_MultipleMatches_ReplaceAll(t *testing.T) {
	content := "a = 1\nb = 1\nc = 1"
	result := Replace(content, "1", "2", true, IndentStyle{UseTabs: false, IndentSize: 4}, false)

	if !result.Applied {
		t.Fatalf("expected match with replace_all=true, got: %s", result.Message)
	}
	want := "a = 2\nb = 2\nc = 2"
	if result.Content != want {
		t.Errorf("got %q, want %q", result.Content, want)
	}
}

func TestReplace_LineEndingPreservation(t *testing.T) {
	// CRLF file
	content := "line1\r\nline2\r\nline3"
	result := Replace(content, "line2", "replaced", false, IndentStyle{UseTabs: false, IndentSize: 4}, false)

	if !result.Applied {
		t.Fatalf("expected match, got: %s", result.Message)
	}
	want := "line1\r\nreplaced\r\nline3"
	if result.Content != want {
		t.Errorf("got %q, want %q", result.Content, want)
	}
}
