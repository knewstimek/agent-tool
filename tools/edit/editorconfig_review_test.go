package edit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEditorConfigCommonPathPatterns(t *testing.T) {
	for _, tt := range []struct{ pattern, rel string }{
		{"**/*.go", "top.go"}, {"src/**/file.go", "src/a/b/file.go"}, {"/src/*.go", "src/file.go"},
	} {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, ".editorconfig"), []byte("root=true\n["+tt.pattern+"]\ncharset=euc-kr\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if got := FindEditorConfigCharset(filepath.Join(d, filepath.FromSlash(tt.rel))); got != "euc-kr" {
			t.Fatalf("%s for %s: charset=%q", tt.pattern, tt.rel, got)
		}
	}
}
func TestEditorConfigTabWidthAndPreambleBOM(t *testing.T) {
	for _, style := range []string{"tab", "space"} {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, ".editorconfig"), []byte("\ufeffroot=true\r[*]\rindent_style="+style+"\rindent_size=tab\rtab_width=8\r"), 0600); err != nil {
			t.Fatal(err)
		}
		got := findEditorConfig(filepath.Join(d, "file.txt"))
		if got == nil || got.UseTabs != (style == "tab") || got.IndentSize != 8 {
			t.Fatalf("style=%s got=%+v", style, got)
		}
	}
}
