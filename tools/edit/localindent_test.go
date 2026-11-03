package edit

import (
	"strings"
	"testing"
)

func TestLocalIndentRecovery(t *testing.T) {
	for _, tt := range []struct {
		name, content, old, replacement, want string
		style                                 IndentStyle
	}{
		{"minority spaces", "\tother\n  target\n", "\ttarget", "\tchanged\n\tmore", "\tother\n  changed\n  more\n", IndentStyle{true, 4}},
		{"mixed alignment", "\t target\r\n", "     target", "     changed\n     more", "\t changed\r\n\t more\r\n", IndentStyle{true, 4}},
		{"deep flat anchor", "\t\ttarget\n", "        target", "        changed\n            nested", "\t\tchanged\n\t\t\tnested\n", IndentStyle{true, 4}},
		{"minority tabs", "    other\n\ttarget\n", "    target", "    changed\n        nested", "    other\n\tchanged\n\t\tnested\n", IndentStyle{false, 4}},
		{"tab stop alignment", " \ttarget\n", "    target", "    changed\n    more", " \tchanged\n \tmore\n", IndentStyle{true, 4}},
		{"shallow source unit", "\t\ttarget\n", "  target", "  changed\n    nested", "\t\tchanged\n\t\t\tnested\n", IndentStyle{true, 4}},
		{"deindent", "\t\ttarget\n", "    target", "changed", "\tchanged\n", IndentStyle{true, 4}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := Replace(tt.content, tt.old, tt.replacement, false, tt.style, false)
			if !got.Applied || got.Content != tt.want {
				t.Fatalf("%s\ngot %q\nwant %q", got.Message, got.Content, tt.want)
			}
		})
	}
}

func TestLocalIndentDoesNotMatchInlineOrGuessDuplicateBodies(t *testing.T) {
	for _, content := range []string{"\tcall(target)\n", " \ttarget\n  target\n"} {
		got := Replace(content, "    target", "    changed\n    more", false, IndentStyle{true, 4}, false)
		if got.Applied || !strings.Contains(got.Message, "not found") {
			t.Fatalf("unexpected match: %+v", got)
		}
	}
}
