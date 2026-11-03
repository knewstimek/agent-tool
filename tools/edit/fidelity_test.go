package edit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceIndentFidelity(t *testing.T) {
	tests := []struct {
		name, content, old, replacement, want string
		style                                 IndentStyle
	}{
		{"converted multiline", "\t\tA\n", "    A", "    X\n    Y", "\t\tX\n\t\tY\n", IndentStyle{true, 4}},
		{"converted CRLF", "\t\tA\r\n", "    A", "    X\n    Y", "\t\tX\r\n\t\tY\r\n", IndentStyle{true, 4}},
		{"converted deep block", "\t\t\tif A {\n\t\t\t\tB\n\t\t\t}\n", "    if A {\n        B\n    }", "    if X {\n        Y\n    }", "\t\t\tif X {\n\t\t\t\tY\n\t\t\t}\n", IndentStyle{true, 4}},
		{"tab depth multiline", "\t\t\tA\n", "\tA", "\tX\n\tY", "\t\t\tX\n\t\t\tY\n", IndentStyle{true, 4}},
		{"space size conversion", "    if A {\n        B\n    }\n", "  if A {\n    B\n  }", "  if X {\n    Y\n  }", "    if X {\n        Y\n    }\n", IndentStyle{false, 4}},
		{"converted tab anchor", "        A\n", "\tA", "\tX\n\tY", "        X\n        Y\n", IndentStyle{false, 4}},
		{"line anchored selection", "\tA\n\t\tA\n", "    A", "    X\n    Y", "\tX\n\tY\n\t\tA\n", IndentStyle{true, 4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Replace(tt.content, tt.old, tt.replacement, false, tt.style, false)
			if !got.Applied || got.Content != tt.want {
				t.Fatalf("applied=%v message=%s\ngot  %q\nwant %q", got.Applied, got.Message, got.Content, tt.want)
			}
		})
	}
}

func TestReplaceAmbiguousConvertedIndent(t *testing.T) {
	for _, all := range []bool{false, true} {
		got := Replace("\tA\n\t\t\tA\n", "\t\tA", "\t\tX\n\t\tY", all, IndentStyle{true, 4}, false)
		if got.Applied || !strings.Contains(got.Message, "equally plausible") {
			t.Fatalf("ambiguous depths must be rejected: %+v", got)
		}
	}
	got := Replace("\tA\n\tA\n", "    A", "    X", false, IndentStyle{true, 4}, false)
	if got.Applied || !strings.Contains(got.Message, "2 times") {
		t.Fatalf("ambiguous converted matches must be rejected: %+v", got)
	}
}

func TestIndentSampling(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		for _, prefix := range []string{"", strings.Repeat("// header"+ending, 1500), strings.Repeat("x", 300*1024) + ending} {
			got := DetectIndentOfString(prefix + "a" + ending + "  b" + ending + "    c")
			if got.UseTabs || got.IndentSize != 2 {
				t.Fatalf("ending=%q prefix=%d: %+v", ending, len(prefix), got)
			}
		}
	}
	// Equal votes choose the smaller observed unit consistently.
	for i := 0; i < 100; i++ {
		if got := DetectIndentOfString("  a\n      b\n"); got.IndentSize != 2 {
			t.Fatalf("tie: %+v", got)
		}
	}
}

func TestIndentDedentationEvidence(t *testing.T) {
	for _, text := range []string{"      a\n    b\n  c\n", "        a\n    b\n"} {
		want := 2
		if strings.HasPrefix(text, "        ") {
			want = 4
		}
		got := DetectIndentOfString(text)
		if got.UseTabs || got.IndentSize != want {
			t.Fatalf("descending nesting: %+v want=%d", got, want)
		}
	}
}

func TestEditorConfigInheritance(t *testing.T) {
	tests := []struct {
		name, parent, child, charset string
		style                        *IndentStyle
	}{
		{"inherit charset", "charset = euc-kr\n", "indent_style = space\nindent_size = 2\n", "euc-kr", &IndentStyle{false, 2}},
		{"inherit size", "indent_style = space\nindent_size = 2\n", "indent_style = space\n", "", &IndentStyle{false, 2}},
		{"override size only", "indent_style = space\nindent_size = 4\n", "indent_size = 2\n", "", &IndentStyle{false, 2}},
		{"inherit style only", "indent_style = space\nindent_size = 4\n", "charset = utf-8\n", "utf-8", &IndentStyle{false, 4}},
		{"unset charset", "charset = euc-kr\nindent_style = space\nindent_size = 2\n", "charset = unset\n", "", &IndentStyle{false, 2}},
		{"override charset", "charset = euc-kr\n", "charset = utf-8\n", "utf-8", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := t.TempDir()
			child := filepath.Join(d, "child")
			if err := os.Mkdir(child, 0700); err != nil {
				t.Fatal(err)
			}
			config := func(dir, text string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, ".editorconfig"), []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			config(d, "root = true\n[*]\n"+tt.parent)
			config(child, "[*]\n"+tt.child)
			p := filepath.Join(child, "a.txt")
			if got := FindEditorConfigCharset(p); got != tt.charset {
				t.Fatalf("charset=%q want=%q", got, tt.charset)
			}
			got := findEditorConfig(p)
			if (got == nil) != (tt.style == nil) || got != nil && *got != *tt.style {
				t.Fatalf("style=%v want=%v", got, tt.style)
			}
		})
	}
}

func TestEditorConfigRootBoundary(t *testing.T) {
	d := t.TempDir()
	child := filepath.Join(d, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, ".editorconfig"), []byte("root=true\n[*]\ncharset=euc-kr\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, preamble := range []string{"# comment\nroot=true\n", "# comment\nroot = TRUE\n"} {
		if err := os.WriteFile(filepath.Join(child, ".editorconfig"), []byte(preamble+"[*.go]\nindent_style=space\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if got := FindEditorConfigCharset(filepath.Join(child, "a.txt")); got != "" {
			t.Fatalf("inherited across root: %q", got)
		}
	}
}

func TestDetectIndentConflictingEditorConfig(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, ".editorconfig"), []byte("root=true\n[*]\nindent_style=tab\nindent_size=4\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got := DetectIndent(filepath.Join(d, "a.txt"), "a\n  b\n    c\n")
	if got.UseTabs || got.IndentSize != 2 {
		t.Fatalf("existing space unit lost: %+v", got)
	}
}
