package grep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestUnreadableWarningAtResultCap(t *testing.T) {
	for _, laterMatch := range []bool{false, true} {
		for _, cap := range []int{1, 2} {
			t.Run(fmt.Sprintf("cap=%d/later_match=%t", cap, laterMatch), func(t *testing.T) {
				d := t.TempDir()
				files := map[string]string{
					"a.txt":         "needle\n",
					"b.txt":         "needle\n",
					".editorconfig": "root=true\n[b.txt]\ncharset=invalid-charset\n",
				}
				if laterMatch {
					files["c.txt"] = "needle\n"
				}
				for name, content := range files {
					if err := os.WriteFile(filepath.Join(d, name), []byte(content), 0600); err != nil {
						t.Fatal(err)
					}
				}
				r, out, err := Handle(context.Background(), nil, GrepInput{
					Path: d, Glob: "*.txt", Pattern: "needle", MaxResults: cap,
				})
				if err != nil || r.IsError {
					t.Fatalf("search failed: %v %+v", err, r)
				}
				var text string
				for _, block := range r.Content {
					if block, ok := block.(*mcp.TextContent); ok {
						text += block.Text
					}
				}
				if !strings.Contains(text, "1 unreadable path(s) skipped; results may be incomplete") {
					t.Fatalf("missing unreadable warning: %s", text)
				}
				wantCount := 1
				if laterMatch && cap == 2 {
					wantCount = 2
				}
				if out.Count != wantCount || out.HasMore != (laterMatch && cap == 1) {
					t.Fatalf("incorrect cap boundary: %+v", out)
				}
			})
		}
	}
}
