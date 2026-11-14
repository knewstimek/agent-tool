package codegraph

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The help taught op= for many releases; it must keep working beside operation.
func TestOpIsAnAliasForOperation(t *testing.T) {
	src := filepath.Join(t.TempDir(), "a.go")
	if err := os.WriteFile(src, []byte("package a\n\nfunc Alpha() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	text := func(in CodeGraphInput) (string, bool) {
		res, _, err := Handle(context.Background(), &mcp.CallToolRequest{}, in)
		if err != nil {
			t.Fatal(err)
		}
		return res.Content[0].(*mcp.TextContent).Text, res.IsError
	}
	byOp, opErr := text(CodeGraphInput{Op: "symbols", Path: src})
	byOperation, operationErr := text(CodeGraphInput{Operation: "symbols", Path: src})
	if opErr || operationErr || byOp != byOperation || !strings.Contains(byOp, "Alpha") {
		t.Errorf("op and operation differ or failed:\nop: %s\noperation: %s", byOp, byOperation)
	}
	if msg, isErr := text(CodeGraphInput{Path: src}); !isErr || !strings.Contains(msg, "operation is required") {
		t.Errorf("neither given: %q (error=%v)", msg, isErr)
	}
}
