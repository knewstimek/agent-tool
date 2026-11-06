package ssh

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func finishedTestJob(t *testing.T, output string) *common.Job {
	t.Helper()
	stdout := common.NewBoundedCapture(1024)
	_, _ = stdout.Write([]byte(output))
	job := common.NewJob("ssh", "ssh operation=start", 0, stdout, common.NewBoundedCapture(1024), func() {})
	job.SetRenderer(renderSSHJob)
	job.SetNote("remote cleanup pending")
	job.Finish(0, nil)
	common.RegisterJob(job)
	return job
}

func TestSSHJobStatusAndTailDoNotRequireConnectionFields(t *testing.T) {
	job := finishedTestJob(t, "one\ntwo\nthree\n")
	result, out, err := Handle(context.Background(), nil, SSHInput{Operation: "tail", JobID: job.ID(), TailLines: 2})
	if err != nil || result.IsError {
		t.Fatalf("Handle() error = %v, result = %#v", err, result)
	}
	if out.Status != "completed" || !strings.Contains(out.Result, "two\nthree") || strings.Contains(out.Result, "one\n") {
		t.Fatalf("unexpected tail result: %q", out.Result)
	}
	if out.CleanupWarning != "remote cleanup pending" || !strings.Contains(out.Result, "cleanup_warning: remote cleanup pending") {
		t.Fatalf("cleanup warning lost: %+v", out)
	}
}

// SSH jobs are in the shared registry, so toolbox operation=job sees them with
// the ssh format, and a finished job's wait/status returns the full output.
func TestSSHJobVisibleThroughSharedJobOperation(t *testing.T) {
	job := finishedTestJob(t, "alpha\nbeta\n")
	res := common.HandleJobOperation(context.Background(), "wait", job.ID(), 1, common.JobRenderOptions{TailLines: 1})
	text := textOf(res)
	if res.IsError || !strings.Contains(text, "alpha\nbeta") || !strings.Contains(text, "exit_code: 0") {
		t.Fatalf("shared wait did not render ssh job output: %q", text)
	}
	if list := textOf(common.HandleJobOperation(context.Background(), "list", "", 0, common.JobRenderOptions{})); !strings.Contains(list, job.ID()) {
		t.Fatalf("ssh job missing from shared list: %q", list)
	}
}

func TestRegisteredStatusDoesNotRequireConnectionFields(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	Register(server)
	registration, ok := common.RegisteredSafeTool(server, "ssh")
	if !ok {
		t.Fatal("ssh SafeAddTool registration not found")
	}
	arguments, err := json.Marshal(map[string]any{
		"operation": "status",
		"job_id":    "missing-test-job",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "ssh", Arguments: arguments}}
	result, err := registration.Handler(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !result.IsError || !strings.Contains(text, `job "missing-test-job" not found`) {
		t.Fatalf("status was blocked before job lookup: isError=%v text=%q", result.IsError, text)
	}
}
