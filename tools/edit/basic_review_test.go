package edit

import "testing"

func TestForceStyleDoesNotMistakeDepthForUnit(t *testing.T) {
	for _, tt := range []struct {
		style IndentStyle
		want  string
	}{
		{IndentStyle{false, 4}, "        changed\n"},
		{IndentStyle{true, 4}, "\t\tchanged\n"},
	} {
		got := Replace("        target\n", "        target", "        changed", false, tt.style, true)
		if !got.Applied || got.Content != tt.want {
			t.Fatalf("got=%q want=%q message=%s", got.Content, tt.want, got.Message)
		}
	}
}

func TestMixedFileBlockPreservesIndentedBlankLine(t *testing.T) {
	got := Replace("\tbegin\n\t\nend\n", "    begin\n    \nend", "    start\n    \nend\n    marker", false, IndentStyle{true, 4}, false)
	want := "\tstart\n\t\nend\n\tmarker\n"
	if !got.Applied || got.Content != want {
		t.Fatalf("got=%q want=%q message=%s", got.Content, want, got.Message)
	}
}

func TestBlockMappingKeepsNestingAndAlignment(t *testing.T) {
	for _, tt := range []struct{ content, old, replacement, want string }{
		{"\t line\nroot\nend\n", "     line\nroot\nend", "     changed\nroot\nend\n     marker", "\t changed\nroot\nend\n\t marker\n"},
		{"   begin\n       child\nend\n", "   begin\n\t  child\nend", "   changed\n\t  child\nend\n   marker", "   changed\n       child\nend\n   marker\n"},
	} {
		got := Replace(tt.content, tt.old, tt.replacement, false, IndentStyle{true, 4}, false)
		if !got.Applied || got.Content != tt.want {
			t.Fatalf("got=%q want=%q message=%s", got.Content, tt.want, got.Message)
		}
	}
	for _, tt := range []struct{ content, old string }{
		{"\ta\n\t\tb\n", "    a\n    b"},
		{"\ta\n\tb\n", "    a\n        b"},
	} {
		got := Replace(tt.content, tt.old, "    changed\n    next", false, IndentStyle{true, 4}, false)
		if got.Applied {
			t.Fatalf("different nesting shape was accepted: %q", got.Content)
		}
	}
}

func TestMixedFileMultilineLocalIndent(t *testing.T) {
	for _, tt := range []struct {
		content, old, replacement, want string
		style                           IndentStyle
	}{
		{"\tother\n  begin\n    child\n  end\n", "\tbegin\n\t\tchild\n\tend", "\tstart\n\t\tchanged\n\tstop", "\tother\n  start\n    changed\n  stop\n", IndentStyle{true, 4}},
		{"    other\n\tbegin\n\t\tchild\n\tend\n", "    begin\n        child\n    end", "    start\n        changed\n    stop", "    other\n\tstart\n\t\tchanged\n\tstop\n", IndentStyle{false, 4}},
	} {
		got := Replace(tt.content, tt.old, tt.replacement, false, tt.style, false)
		if !got.Applied || got.Content != tt.want {
			t.Fatalf("got=%q want=%q message=%s", got.Content, tt.want, got.Message)
		}
	}
}
