package procexec

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestForegroundTimeoutHelper(t *testing.T) {
	if os.Getenv("AGENT_TOOL_TIMEOUT_HELPER") == "1" {
		fmt.Println("started")
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

func helperInput() ProcExecInput {
	return ProcExecInput{
		Command: os.Args[0], Args: []string{"-test.run=^TestForegroundTimeoutHelper$"},
		Env: []string{"AGENT_TOOL_TIMEOUT_HELPER=1"}, MaxOutputChars: common.DefaultOutputChars,
		OutputView: "compact", TailLines: defaultTailLines,
	}
}

func text(r *mcp.CallToolResult) string { return r.Content[0].(*mcp.TextContent).Text }

func TestTimeoutBeforeYieldKillsAndReports(t *testing.T) {
	r, out, err := execJob(context.Background(), helperInput(), runOptions{timeout: time.Second, yieldAfter: 10 * time.Second})
	if err != nil || !r.IsError || out.Status != common.JobTimedOut || !strings.Contains(text(r), "timed out") {
		t.Fatalf("timeout reported as normal completion: result=%q out=%+v err=%v", text(r), out, err)
	}
	if !strings.Contains(out.Stdout, "started") {
		t.Fatalf("partial output before timeout was lost: %+v", out)
	}
}

func TestYieldReturnsJobThenWaitAndCancel(t *testing.T) {
	start := time.Now()
	r, out, err := execJob(context.Background(), helperInput(), runOptions{timeout: time.Minute, yieldAfter: 500 * time.Millisecond})
	if err != nil || r.IsError || out.Status != common.JobRunning || out.JobID == "" {
		t.Fatalf("expected yielded running job: result=%q out=%+v err=%v", text(r), out, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("yield blocked too long: %s", time.Since(start))
	}
	if !strings.Contains(text(r), "operation=wait job_id="+out.JobID) {
		t.Fatalf("yield result lacks next-step hint: %q", text(r))
	}

	r, out2, _ := Handle(context.Background(), nil, ProcExecInput{Operation: "wait", JobID: out.JobID, WaitSec: 1})
	if out2.Status != common.JobRunning || r.IsError {
		t.Fatalf("short wait should report still running: %q", text(r))
	}

	r, out3, _ := Handle(context.Background(), nil, ProcExecInput{Operation: "cancel", JobID: out.JobID})
	if out3.Status != common.JobCancelled || !strings.Contains(text(r), "started") {
		t.Fatalf("cancel did not finish the job: %q", text(r))
	}

	r, _, _ = Handle(context.Background(), nil, ProcExecInput{Operation: "list"})
	if !strings.Contains(text(r), out.JobID) {
		t.Fatalf("list misses job: %q", text(r))
	}
}

func TestBackgroundCapturesOutput(t *testing.T) {
	_, out, err := execJob(context.Background(), ProcExecInput{
		Command: os.Args[0], Args: []string{"-test.run=^TestProcExecHelperProcess$"},
		Env: []string{"AGENT_TOOL_PROCEXEC_HELPER=1"}, MaxOutputChars: common.DefaultOutputChars,
		OutputView: "raw", TailLines: defaultTailLines,
	}, runOptions{})
	if err != nil || out.JobID == "" {
		t.Fatalf("background start failed: %+v %v", out, err)
	}
	r, out2, _ := Handle(context.Background(), nil, ProcExecInput{Operation: "wait", JobID: out.JobID, WaitSec: 30, OutputView: "raw"})
	if out2.Status != common.JobCompleted || strings.Count(out2.Stderr, "warning: duplicated diagnostic") != 3 {
		t.Fatalf("background output not captured: %q", text(r))
	}
}

// Registration builds the JSON schema from struct tags; a bad tag only panics
// at registration time, which the direct handler tests never reach.
func TestRegisterBuildsSchema(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	Register(server)
	if _, ok := common.RegisteredSafeTool(server, "procexec"); !ok {
		t.Fatal("procexec registration not found")
	}
}

func TestUnknownJobIsActionable(t *testing.T) {
	r, _, _ := Handle(context.Background(), nil, ProcExecInput{Operation: "status", JobID: "nope"})
	if !r.IsError || !strings.Contains(text(r), "job_action=list") {
		t.Fatalf("unhelpful missing-job error: %q", text(r))
	}
}
