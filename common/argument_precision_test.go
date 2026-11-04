package common

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestSafeToolPreservesIntegerArguments(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	type input struct {
		Value uint64 `json:"value"`
	}
	var got uint64
	SafeAddTool(server, &mcp.Tool{Name: "integer"}, func(_ context.Context, _ *mcp.CallToolRequest, in input) (*mcp.CallToolResult, struct{}, error) {
		got = in.Value
		return &mcp.CallToolResult{}, struct{}{}, nil
	})
	registration, _ := RegisteredSafeTool(server, "integer")
	for _, tt := range []struct {
		raw  string
		want uint64
	}{
		{`{"value":9007199254740993}`, 9007199254740993},
		{`{"value":"9007199254740993"}`, 9007199254740993},
		{`{"value":18446744073709551615}`, ^uint64(0)},
		{`{"value":"18446744073709551615"}`, ^uint64(0)},
	} {
		t.Run(fmt.Sprint(tt.want, "/", tt.raw), func(t *testing.T) {
			got = 0
			r, err := registration.Handler(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{
				Name: "integer", Arguments: json.RawMessage(tt.raw),
			}})
			if err != nil || r.IsError || got != tt.want {
				t.Fatalf("integer changed: got=%d want=%d result=%+v err=%v", got, tt.want, r, err)
			}
		})
	}
}
