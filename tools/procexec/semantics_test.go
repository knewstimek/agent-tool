package procexec

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"agent-tool/common"
)

func TestTailHelper(t *testing.T) {
	if os.Getenv("AGENT_TOOL_TAIL_HELPER") == "1" {
		for i := 0; i < 50; i++ {
			os.Stdout.WriteString("refresh frame " + strings.Repeat("x", 40) + "\n")
		}
		os.Stdout.WriteString("FINAL LINE\n")
		os.Exit(0)
	}
}

func startJob(t *testing.T, env string, opts runOptions) ProcExecOutput {
	t.Helper()
	_, out, err := execJob(context.Background(), ProcExecInput{
		Command: os.Args[0], Args: []string{"-test.run=^(TestTailHelper|TestForegroundTimeoutHelper)$"},
		Env: []string{env}, MaxOutputChars: common.DefaultOutputChars, OutputView: "compact", TailLines: defaultTailLines,
	}, opts)
	if err != nil || out.JobID == "" {
		t.Fatalf("job not started: %+v %v", out, err)
	}
	return out
}

// A cancel the agent asked for is a success, not a failed call; cancelling a
// job that already finished is not an error either.
func TestRequestedCancelIsNotAnError(t *testing.T) {
	out := startJob(t, "AGENT_TOOL_TIMEOUT_HELPER=1", runOptions{timeout: time.Minute, yieldAfter: 200 * time.Millisecond})
	r, _, _ := Handle(context.Background(), nil, ProcExecInput{Operation: "cancel", JobID: out.JobID})
	if r.IsError || !strings.Contains(text(r), "cancelled") {
		t.Fatalf("successful cancel flagged as error: isError=%v %q", r.IsError, text(r))
	}
	r, _, _ = Handle(context.Background(), nil, ProcExecInput{Operation: "cancel", JobID: out.JobID})
	if r.IsError || !strings.Contains(text(r), "already finished") {
		t.Fatalf("cancel of finished job: isError=%v %q", r.IsError, text(r))
	}
	if res := common.HandleJobOperation(context.Background(), "status", out.JobID, 0, common.JobRenderOptions{}); res.IsError {
		t.Fatalf("status of a cancelled job flagged as error")
	}
}

// Explicit tail_lines on wait returns only the tail of a finished job, so
// refresh-style output is not replayed in full.
func TestWaitWithExplicitTailReturnsOnlyTail(t *testing.T) {
	out := startJob(t, "AGENT_TOOL_TAIL_HELPER=1", runOptions{timeout: time.Minute})
	r, _, _ := Handle(context.Background(), nil, ProcExecInput{Operation: "wait", JobID: out.JobID, WaitSec: 30, TailLines: 2})
	got := text(r)
	if !strings.Contains(got, "FINAL LINE") || strings.Count(got, "refresh frame") > 1 || !strings.Contains(got, "omit tail_lines") {
		t.Fatalf("tail-only wait returned: %q", got)
	}
	r, _, _ = Handle(context.Background(), nil, ProcExecInput{Operation: "status", JobID: out.JobID})
	if strings.Count(text(r), "refresh frame") < 50 {
		t.Fatalf("default status should still return full output")
	}
}

// Background log paths appear at start and at the end, not on every poll.
func TestLogPathsNotRepeatedWhileRunning(t *testing.T) {
	_, out, _ := execJob(context.Background(), ProcExecInput{
		Command: os.Args[0], Args: []string{"-test.run=^TestForegroundTimeoutHelper$"},
		Env: []string{"AGENT_TOOL_TIMEOUT_HELPER=1"}, MaxOutputChars: common.DefaultOutputChars, OutputView: "compact", TailLines: defaultTailLines,
	}, runOptions{})
	defer Handle(context.Background(), nil, ProcExecInput{Operation: "cancel", JobID: out.JobID})
	r, _, _ := Handle(context.Background(), nil, ProcExecInput{Operation: "status", JobID: out.JobID})
	if strings.Contains(text(r), "Logs:") {
		t.Fatalf("running status repeated log paths: %q", text(r))
	}
	r, _, _ = Handle(context.Background(), nil, ProcExecInput{Operation: "cancel", JobID: out.JobID})
	if !strings.Contains(text(r), "Logs:") {
		t.Fatalf("final result should show log paths: %q", text(r))
	}
}
