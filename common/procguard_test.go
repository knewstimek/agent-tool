package common

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestGuardSleepHelper(t *testing.T) {
	if os.Getenv("AGENT_TOOL_GUARD_SLEEP") == "1" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

// Kill after Close must not act: Close marks the process as reaped, after
// which a PID-based fallback could hit an unrelated process reusing the PID.
func TestGuardKillAfterCloseIsNoOp(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestGuardSleepHelper$")
	cmd.Env = append(os.Environ(), "AGENT_TOOL_GUARD_SLEEP=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()

	g, _ := GuardProcess(cmd.Process, GuardOptions{})
	g.Close()
	g.Kill()
	select {
	case <-done:
		t.Fatal("Kill after Close terminated the process")
	case <-time.After(500 * time.Millisecond):
	}

	g2, _ := GuardProcess(cmd.Process, GuardOptions{})
	g2.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Kill before Close did not terminate the process")
	}
}

type waitProbeInput struct {
	Operation string `json:"operation,omitempty" jsonschema:"operation"`
}

// operation=wait is a bounded, deliberate block; yielding it would wrap a
// job in another job.
func TestExplicitWaitIsNotYielded(t *testing.T) {
	withYield(t, 50*time.Millisecond)
	server := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "t"}, nil)
	SafeAddYieldingTool(server, &mcp.Tool{Name: "waitprobe", Description: "probe"},
		func(ctx context.Context, req *mcp.CallToolRequest, in waitProbeInput) (*mcp.CallToolResult, struct{}, error) {
			time.Sleep(300 * time.Millisecond)
			return ok("done " + in.Operation), struct{}{}, nil
		})
	reg, _ := RegisteredSafeTool(server, "waitprobe")
	call := func(op string) string {
		args, _ := json.Marshal(map[string]any{"operation": op})
		r, err := reg.Handler(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "waitprobe", Arguments: args}})
		if err != nil {
			t.Fatal(err)
		}
		return textOf(r)
	}
	if got := call("wait"); got != "done wait" {
		t.Fatalf("wait was yielded: %q", got)
	}
	if got := call("execute"); !strings.Contains(got, "still running") {
		t.Fatalf("non-wait slow call should yield: %q", got)
	}
}
