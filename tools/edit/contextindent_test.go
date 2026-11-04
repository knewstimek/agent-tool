package edit

import (
	"strings"
	"testing"
)

func TestStructuralIndentIgnoresAlignmentAndLiterals(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		for _, tt := range []struct{ name, text string }{
			{"calls", "void f() {\n    call(\n      one,\n       two,\n        three);\n    if (ok) {\n        work();\n    }\n}\n"},
			{"comments", "void f() {\n    /* fake {\n      fake {\n        fake\n      fake\n    */\n    work();\n}\n"},
			{"strings", "void f() {\n    auto s = R\"tag(fake {\n      fake {\n        fake\n      fake\n)tag\";\n    work();\n}\n"},
			{"python", "def f():\n    text = \"\"\"fake:\n      fake:\n        fake\n      fake\n\"\"\"\n    call(\n      one,\n       two,\n        three)\n"},
			{"backticks", "func f() {\n    s := `fake {\n      fake {\n        fake\n      fake\n`\n    work()\n}\n"},
			{"brackets in strings", "void f() {\n    log(\"[ ( {\"); // fake {\n    if (ready) {\n        work();\n    }\n}\n"},
		} {
			t.Run(tt.name+ending, func(t *testing.T) {
				got := DetectIndentOfString(strings.ReplaceAll(tt.text, "\n", ending))
				if got.UseTabs || got.IndentSize != 4 {
					t.Fatalf("got %+v, want four spaces", got)
				}
			})
		}
	}
}

func TestLocalStructuralWidthRecovery(t *testing.T) {
	// The file majority is four spaces. The edited function uses two.
	majority := strings.Repeat("void other() {\n    work();\n}\n", 40)
	content := majority + "void local() {\n  if (ready) {\n    target();\n  }\n}\n"
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		input := strings.ReplaceAll(content, "\n", ending)
		got := Replace(input, "\ttarget();", "\tif (fresh) {\n\t\tadded();\n\t}", false, DetectIndentOfString(input), false)
		want := strings.Replace(input, "    target();", strings.ReplaceAll("    if (fresh) {\n      added();\n    }", "\n", ending), 1)
		if !got.Applied || got.Content != want {
			t.Fatalf("ending %q: %s\ngot %q\nwant %q", ending, got.Message, got.Content, want)
		}
	}
}

func TestSourceBlockWidthRecovery(t *testing.T) {
	content := "void f() {\n    target();\n}\n"
	// A two-space source snippet should become one target level, rather than
	// retaining the file-wide four-space source guess for a flat old anchor.
	got := Replace(content, "        target();", "        if (fresh) {\n          added();\n        }", false, IndentStyle{false, 4}, false)
	want := "void f() {\n    if (fresh) {\n        added();\n    }\n}\n"
	if !got.Applied || got.Content != want {
		t.Fatalf("%s\ngot %q\nwant %q", got.Message, got.Content, want)
	}
}

func TestLongOpaqueLiteralHasBoundedAllocations(t *testing.T) {
	content := "def f():\n    text = \"\"\"\n" + strings.Repeat("fake { ", 80*1024) + "\n\"\"\"\n    work()\n"
	allocs := testing.AllocsPerRun(3, func() {
		width, ok := structuralIndentWidth(content, -1)
		if !ok || width != 4 {
			t.Fatalf("unexpected width %d %v", width, ok)
		}
	})
	if allocs > 32 {
		t.Fatalf("large literal allocated %.0f objects", allocs)
	}
}

func TestStructuralIndentBoundaries(t *testing.T) {
	// More distant evidence must not leak into the local window.
	far := "void f() {\n  body();\n}\n" + strings.Repeat("// spacer\n", 40)
	if got := localIndentWidth(far+"    target();\n", len(far), 4); got != 4 {
		t.Fatalf("distant evidence changed fallback: %d", got)
	}
	huge := strings.Repeat(" ", 8*1024*1024) + "\nvoid f() {\n  body();\n}\n"
	if _, ok := structuralIndentWidth(huge, 8*1024*1024+1); ok {
		t.Fatal("local scan escaped sample bound")
	}
	// Macro bodies, verbatim literals and explicit line continuations are opaque.
	for _, text := range []string{
		"#define X \\\n  if (fake) { \\\n    fake(); \\\n  }\n",
		"var text = @\"fake {\n  fake {\n    fake\n  fake\n\";\n",
		"call \\\n  continued {\n    fake\n",
	} {
		if _, ok := structuralIndentWidth(text, -1); ok {
			t.Fatalf("unexpected evidence: %q", text)
		}
	}
}

func TestStructuralIndentInconclusiveFallback(t *testing.T) {
	for _, text := range []string{
		"call(\n  one,\n    two);\n",
		"// fake {\n  fake\n",
		"\"fake {\"\n  fake\n",
		"if (a) {\n  a();\n}\nif (b) {\n    b();\n}\n",
	} {
		if width, ok := structuralIndentWidth(text, -1); ok {
			t.Fatalf("guessed %d for %q", width, text)
		}
	}
	// Explicit style and direct replacements retain their established contract.
	got := Replace("    target();\n", "    target();", "    if (ok) {\n      added();\n    }", false, IndentStyle{false, 4}, false)
	if !got.Applied || got.Content != "    if (ok) {\n      added();\n    }\n" {
		t.Fatalf("direct match changed: %+v", got)
	}
}
