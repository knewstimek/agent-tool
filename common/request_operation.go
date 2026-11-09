package common

import (
	"context"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type requestOperationKey struct{}
type requestOperation struct {
	session     *mcp.ServerSession
	rootOnce    sync.Once
	root        string
	aliasesOnce sync.Once
	aliases     map[string]map[string]string
}

// WithToolRequest is lazy: unrelated tools do not fetch roots or copy aliases.
// Nested toolbox calls retain the same operation and owning MCP session.
func WithToolRequest(ctx context.Context, req *mcp.CallToolRequest) context.Context {
	current, _ := ctx.Value(requestOperationKey{}).(*requestOperation)
	if req == nil && current != nil {
		return ctx
	}
	var session *mcp.ServerSession
	if req != nil {
		session = req.Session
	}
	if current != nil && current.session == session {
		return ctx
	}
	return context.WithValue(ctx, requestOperationKey{}, &requestOperation{session: session})
}

func operationFor(ctx context.Context) *requestOperation {
	state, _ := ctx.Value(requestOperationKey{}).(*requestOperation)
	return state
}

func ToolSession(ctx context.Context) *mcp.ServerSession {
	if state := operationFor(ctx); state != nil {
		return state.session
	}
	return nil
}

func operationAliasMap(ctx context.Context, req *mcp.CallToolRequest, scope string) map[string]string {
	state := operationFor(ctx)
	if state == nil {
		return nil
	}
	state.aliasesOnce.Do(func() {
		key := aliasKey(ctx, req)
		directoryAliases.RLock()
		defer directoryAliases.RUnlock()
		state.aliases = make(map[string]map[string]string)
		// Registry updates replace whole inner maps; no mutable map escapes.
		for name, values := range directoryAliases.sessions[key] {
			state.aliases[name] = values
		}
	})
	result := make(map[string]string)
	for name, p := range state.aliases[scope] {
		result[name] = p
	}
	return result
}
