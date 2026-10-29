package toolbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"agent-tool/tools/analyze"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAnnotationPatchThroughToolbox(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "v1"}, nil)
	manager := NewManager(server, []Spec{{Name: "analyze", Group: "analysis",
		Register: func() { analyze.Register(server) }}}, "v1")
	dir := t.TempDir()
	bin, db := filepath.Join(dir, "sample.bin"), filepath.Join(dir, "notes.sqlite")
	if err := os.WriteFile(bin, []byte{0xc3}, 0o600); err != nil {
		t.Fatal(err)
	}
	invoke := func(args map[string]any) string {
		t.Helper()
		args["file_path"], args["annotations_path"] = bin, db
		result, out, err := manager.Handle(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "toolbox"}}, Input{Operation: "call", Tool: "analyze", Arguments: args})
		if err != nil || result.IsError {
			t.Fatalf("toolbox call: %v / %s", err, out.Result)
		}
		// Toolbox preserves raw tool text in the MCP content.
		for _, c := range result.Content {
			if text, ok := c.(*mcp.TextContent); ok {
				return text.Text
			}
		}
		t.Fatal("no tool text")
		return ""
	}
	type note struct {
		ID       string `json:"id"`
		Revision string `json:"revision"`
		Label    string `json:"label"`
		Comment  string `json:"comment"`
	}
	type reply struct {
		Items []note `json:"annotations"`
	}
	var saved reply
	text := invoke(map[string]any{"operation": "annotation_set", "va": "0x0", "label": "entry", "comment": "initial"})
	if err := json.Unmarshal([]byte(text), &saved); err != nil || len(saved.Items) != 1 {
		t.Fatalf("creation receipt: %s / %v", text, err)
	}
	var updated reply
	text = invoke(map[string]any{"operation": "annotation_set", "annotation_id": saved.Items[0].ID,
		"expected_revision": saved.Items[0].Revision,
		"annotation_patch":  map[string]any{"label": "", "comment": "edited through MCP"}})
	if err := json.Unmarshal([]byte(text), &updated); err != nil || len(updated.Items) != 1 ||
		updated.Items[0].Label != "" || updated.Items[0].Comment != "edited through MCP" || updated.Items[0].Revision != "2" {
		t.Fatalf("JSON patch was not preserved: %s / %v", text, err)
	}
}
