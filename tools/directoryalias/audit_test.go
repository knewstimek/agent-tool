package directoryalias

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestOneCallKeepsOneAliasVersion(t *testing.T) {
	root := t.TempDir()
	old := common.GetWorkspace()
	common.SetWorkspace(root)
	t.Cleanup(func() { common.SetWorkspace(old) })
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	for _, p := range []string{a, b} {
		if err := os.Mkdir(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "audit", Version: "test"}, nil)
	Register(server)
	first, release := make(chan struct{}), make(chan struct{})
	common.SafeAddTool(server, &mcp.Tool{Name: "pair"}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, struct{}, error) {
		left, err := common.ResolveRequestPath(ctx, req, "@src/left")
		if err != nil {
			return nil, struct{}{}, err
		}
		close(first)
		<-release
		right, err := common.ResolveRequestPath(ctx, req, "@src/right")
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: left + "\n" + right}}}, struct{}{}, err
	})
	req, peer := testSession(t, server)
	if r, _, err := Handle(t.Context(), req, Input{Operation: "set", Aliases: map[string]string{"src": a}}); err != nil || r.IsError {
		t.Fatal("setup failed")
	}
	finished := make(chan *mcp.CallToolResult, 1)
	go func() {
		r, err := peer.CallTool(t.Context(), &mcp.CallToolParams{Name: "pair"})
		if err != nil {
			finished <- nil
		} else {
			finished <- r
		}
	}()
	<-first
	r, _, err := Handle(t.Context(), req, Input{Operation: "set", Aliases: map[string]string{"src": b}, Overwrite: true})
	close(release)
	result := <-finished
	if err != nil || r.IsError || result == nil || result.IsError {
		t.Fatal("pair operation failed")
	}
	got := textOf(t, result)
	if got != filepath.Join(a, "left")+"\n"+filepath.Join(a, "right") {
		t.Errorf("one call mixed alias versions: %q", got)
	}
}

func TestYieldedJobsCannotCrossSessions(t *testing.T) {
	oldYield := common.YieldAfter
	common.YieldAfter = time.Millisecond
	t.Cleanup(func() { common.YieldAfter = oldYield })
	server := mcp.NewServer(&mcp.Implementation{Name: "audit", Version: "test"}, nil)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	common.SafeAddYieldingTool(server, &mcp.Tool{Name: "private_work"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, struct{}, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "PRIVATE_RESULT"}}}, struct{}{}, nil
	})
	type jobInput struct {
		Op string `json:"op"`
		ID string `json:"id"`
	}
	common.SafeAddTool(server, &mcp.Tool{Name: "inspect_job"}, func(ctx context.Context, _ *mcp.CallToolRequest, in jobInput) (*mcp.CallToolResult, struct{}, error) {
		return common.HandleJobOperation(ctx, in.Op, in.ID, 1, common.JobRenderOptions{}), struct{}{}, nil
	})
	_, owner := testSession(t, server)
	_, other := testSession(t, server)
	yielded, err := owner.CallTool(t.Context(), &mcp.CallToolParams{Name: "private_work"})
	if err != nil || yielded.IsError {
		t.Fatal("yield failed")
	}
	text := textOf(t, yielded)
	at := strings.Index(text, "job_id=")
	if at < 0 {
		t.Fatal("did not yield")
	}
	id := strings.Fields(text[at+len("job_id="):])[0]
	for _, op := range []string{"status", "tail", "cancel", "wait"} {
		r, err := other.CallTool(t.Context(), &mcp.CallToolParams{Name: "inspect_job", Arguments: map[string]any{"op": op, "id": id}})
		if err != nil || !r.IsError {
			t.Errorf("foreign session accepted %s: %+v %v", op, r, err)
		}
	}
	listed, err := other.CallTool(t.Context(), &mcp.CallToolParams{Name: "inspect_job", Arguments: map[string]any{"op": "list"}})
	if err != nil || strings.Contains(textOf(t, listed), id) {
		t.Errorf("foreign session listed job")
	}
	once.Do(func() { close(release) })
	result, err := owner.CallTool(t.Context(), &mcp.CallToolParams{Name: "inspect_job", Arguments: map[string]any{"op": "wait", "id": id}})
	var combined strings.Builder
	if result != nil {
		for _, content := range result.Content {
			if block, ok := content.(*mcp.TextContent); ok {
				combined.WriteString(block.Text)
			}
		}
	}
	if err != nil || result == nil || result.IsError || !strings.Contains(combined.String(), "PRIVATE_RESULT") {
		t.Errorf("owner lost its result: result=%+v err=%v text=%q", result, err, combined.String())
	}
}
