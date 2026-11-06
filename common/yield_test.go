package common

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func textOf(r *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range r.Content {
		sb.WriteString(c.(*mcp.TextContent).Text)
	}
	return sb.String()
}

func withYield(t *testing.T, d time.Duration) {
	old := YieldAfter
	YieldAfter = d
	t.Cleanup(func() { YieldAfter = old })
}

func ok(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func TestYieldFastCallReturnsResultDirectly(t *testing.T) {
	withYield(t, 10*time.Second) // generous: these assert the non-yield path, which must not lose a race to a loaded scheduler
	r := runYielding(context.Background(), "t", "t", func(context.Context) *mcp.CallToolResult { return ok("fast") })
	if textOf(r) != "fast" {
		t.Fatalf("fast call was wrapped: %q", textOf(r))
	}
}

func jobIDFrom(t *testing.T, text string) string {
	t.Helper()
	i := strings.Index(text, "job_id=")
	if i < 0 {
		t.Fatalf("no job_id in %q", text)
	}
	return strings.Fields(strings.TrimRight(text[i+len("job_id="):], ","))[0]
}

func TestYieldSlowCallBecomesJobAndWaitReturnsResult(t *testing.T) {
	withYield(t, 50*time.Millisecond)
	release := make(chan struct{})
	r := runYielding(context.Background(), "slow", "slow", func(context.Context) *mcp.CallToolResult {
		<-release
		return ok("final answer")
	})
	text := textOf(r)
	if r.IsError || !strings.Contains(text, "still running") || !strings.Contains(text, "job_action=wait") {
		t.Fatalf("expected yield notice, got %q", text)
	}
	id := strings.TrimSuffix(jobIDFrom(t, text), ",")
	if res := HandleJobOperation(context.Background(), "status", id, 0, JobRenderOptions{}); !strings.Contains(textOf(res), "still running") {
		t.Fatalf("status before completion: %q", textOf(res))
	}
	close(release)
	res := HandleJobOperation(context.Background(), "wait", id, 5, JobRenderOptions{})
	if res.IsError || !strings.Contains(textOf(res), "final answer") || !strings.Contains(textOf(res), "completed") {
		t.Fatalf("wait did not return final result: %q", textOf(res))
	}
}

func TestYieldCancelStopsWorkThroughContext(t *testing.T) {
	withYield(t, 50*time.Millisecond)
	r := runYielding(context.Background(), "c", "c", func(ctx context.Context) *mcp.CallToolResult {
		<-ctx.Done()
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "stopped: " + ctx.Err().Error()}}, IsError: true}
	})
	id := strings.TrimSuffix(jobIDFrom(t, textOf(r)), ",")
	res := HandleJobOperation(context.Background(), "cancel", id, 0, JobRenderOptions{})
	if !strings.Contains(textOf(res), "cancelled") || !strings.Contains(textOf(res), "stopped: context canceled") {
		t.Fatalf("cancel did not reach the work: %q", textOf(res))
	}
}

func TestYieldWorkSurvivesRequestEndButNotEarlyCancel(t *testing.T) {
	withYield(t, 10*time.Second) // generous: these assert the non-yield path, which must not lose a race to a loaded scheduler
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	r := runYielding(ctx, "e", "e", func(wctx context.Context) *mcp.CallToolResult {
		<-wctx.Done()
		close(stopped)
		return ok("x")
	})
	if !r.IsError || !strings.Contains(textOf(r), "canceled") {
		t.Fatalf("abandoned call should report cancel: %q", textOf(r))
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("work kept running after the client abandoned the call before yield")
	}
}

func TestCancelSemanticsForResultJobs(t *testing.T) {
	withYield(t, 20*time.Millisecond)
	oldGrace := cancelGrace
	cancelGrace = 50 * time.Millisecond
	t.Cleanup(func() { cancelGrace = oldGrace })

	// Work that honors ctx: a requested cancel succeeds and is not an error.
	r := runYielding(context.Background(), "a", "a", func(ctx context.Context) *mcp.CallToolResult {
		<-ctx.Done()
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "stopped"}}, IsError: true}
	})
	id := jobIDFrom(t, textOf(r))
	if res := HandleJobOperation(context.Background(), "cancel", id, 0, JobRenderOptions{}); res.IsError || !strings.Contains(textOf(res), "cancelled") {
		t.Fatalf("requested cancel reported as error: %v %q", res.IsError, textOf(res))
	}
	if res := HandleJobOperation(context.Background(), "cancel", id, 0, JobRenderOptions{}); res.IsError || !strings.Contains(textOf(res), "already finished") {
		t.Fatalf("cancel of finished job: %v %q", res.IsError, textOf(res))
	}

	// Work that needs a moment to stop: say so instead of a bare "still running".
	release := make(chan struct{})
	r = runYielding(context.Background(), "b", "b", func(ctx context.Context) *mcp.CallToolResult {
		<-release
		return ok("late")
	})
	id = jobIDFrom(t, textOf(r))
	res := HandleJobOperation(context.Background(), "cancel", id, 0, JobRenderOptions{})
	close(release)
	if res.IsError || !strings.Contains(textOf(res), "still stopping") {
		t.Fatalf("slow-stopping cancel: %v %q", res.IsError, textOf(res))
	}
}

func TestYieldRecoversPanicInWorker(t *testing.T) {
	withYield(t, 10*time.Second) // generous: these assert the non-yield path, which must not lose a race to a loaded scheduler
	r := runYielding(context.Background(), "p", "p", func(context.Context) *mcp.CallToolResult { panic("boom") })
	if !r.IsError || !strings.Contains(textOf(r), "panic in p") {
		t.Fatalf("panic not converted: %q", textOf(r))
	}
}
