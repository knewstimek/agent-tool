package toolbox

import (
	"context"
	"encoding/json"
	"testing"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRegisteredGatewayPreservesNestedIntegers(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	type input struct {
		Values []uint64 `json:"values"`
	}
	var got []uint64
	manager := NewManager(server, []Spec{{
		Name: "integers", Group: "core", Register: func() {
			common.SafeAddTool(server, &mcp.Tool{Name: "integers"}, func(_ context.Context, _ *mcp.CallToolRequest, in input) (*mcp.CallToolResult, struct{}, error) {
				got = in.Values
				return &mcp.CallToolResult{}, struct{}{}, nil
			})
		},
	}})
	manager.RegisterTool()
	registration, _ := common.RegisteredSafeTool(server, "toolbox")
	r, err := registration.Handler(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{
		Name: "toolbox", Arguments: json.RawMessage(`{"operation":"call","tool":"integers","arguments":{"values":[9007199254740993,18446744073709551615]}}`),
	}})
	if err != nil || r.IsError || len(got) != 2 || got[0] != 9007199254740993 || got[1] != ^uint64(0) {
		t.Fatalf("gateway changed integers: got=%v result=%+v err=%v", got, r, err)
	}
}
