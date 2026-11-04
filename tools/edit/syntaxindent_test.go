package edit

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"agent-tool/tools/codegraph"
)

func TestSyntaxIndentEvaluation(t *testing.T) {
	data, err := os.ReadFile("testdata/syntax_indent.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Path, Content, Old, Replacement, Want string
		AllowErrors, BaselineOnly                   bool
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	total, improved, baselineCorrect := 0, 0, 0
	for _, tt := range cases {
		for _, ending := range []string{"\n", "\r\n", "\r"} {
			t.Run(tt.Name+ending, func(t *testing.T) {
				content := strings.ReplaceAll(tt.Content, "\n", ending)
				style := DetectIndentOfString(content)
				want := strings.ReplaceAll(tt.Want, "\n", ending)
				baseline := Replace(content, tt.Old, tt.Replacement, false, style, false)
				got := ReplaceFile(context.Background(), tt.Path, content, tt.Old, tt.Replacement, false, style, false)
				total++
				if baseline.Applied && baseline.Content == want {
					baselineCorrect++
				}
				if !got.Applied || got.Content != want {
					t.Fatalf("%s\ngot %q\nwant %q", got.Message, got.Content, want)
				}
				if baseline.Content != want {
					improved++
				}
				if tt.BaselineOnly && got.Content != baseline.Content {
					t.Fatal("fallback changed")
				}
				if !tt.BaselineOnly && !tt.AllowErrors {
					lang := "cpp"
					if strings.HasSuffix(tt.Path, ".py") {
						lang = "python"
					}
					tree, err := codegraph.ParseSyntaxTree(context.Background(), lang, tt.Want)
					if err != nil || tree.Nodes[0].HasError {
						t.Fatalf("expected result has syntax errors: %v", err)
					}
				}
			})
		}
	}
	t.Logf("hand-authored cases=%d baseline_correct=%d improved=%d", total, baselineCorrect, improved)
}

func TestSyntaxAnalysisDoesNotChangeForcedOrCanceledFallback(t *testing.T) {
	content := "void f() {\n    target();\n}\n"
	old, newText := "\ttarget();", "\tchanged();"
	style := IndentStyle{false, 4}
	baseline := Replace(content, old, newText, false, style, true)
	got := ReplaceFile(context.Background(), "sample.cpp", content, old, newText, false, style, true)
	if got.Content != baseline.Content || got.Applied != baseline.Applied {
		t.Fatal("forced style changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	baseline = Replace(content, old, newText, false, style, false)
	got = ReplaceFile(ctx, "sample.cpp", content, old, newText, false, style, false)
	if got.Content != baseline.Content || got.Applied != baseline.Applied {
		t.Fatal("canceled analysis changed fallback")
	}
}
