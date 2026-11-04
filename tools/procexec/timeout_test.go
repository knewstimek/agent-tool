package procexec

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestForegroundTimeoutHelper(t *testing.T) {
	if os.Getenv("AGENT_TOOL_TIMEOUT_HELPER") == "1" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

func TestForegroundReportsTimeout(t *testing.T) {
	r, out, err := execForeground(context.Background(), ProcExecInput{
		Command: os.Args[0], Args: []string{"-test.run=^TestForegroundTimeoutHelper$"},
		Env: []string{"AGENT_TOOL_TIMEOUT_HELPER=1"}, MaxOutputChars: common.DefaultOutputChars,
	}, 1)
	if err != nil || !r.IsError || !strings.Contains(r.Content[0].(*mcp.TextContent).Text, "timed out") {
		t.Fatalf("timeout reported as normal completion: result=%+v out=%+v err=%v", r, out, err)
	}
}
