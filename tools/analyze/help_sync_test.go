package analyze

import (
	"context"
	"strings"
	"testing"

	"agent-tool/tools/help"
)

// Every operation must be reachable as agent_tool_help topic="analyze/<op>":
// the analyze index is the only place an agent learns the per-operation guide
// exists, so an operation without a section is undocumented in practice.
func TestEveryOperationHasHelpSection(t *testing.T) {
	_, index, err := help.Handle(context.Background(), nil, help.HelpInput{Topic: "analyze"})
	if err != nil {
		t.Fatal(err)
	}
	for op := range validOperations {
		_, out, err := help.Handle(context.Background(), nil, help.HelpInput{Topic: "analyze/" + op})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.Content, "No section named") || !strings.Contains(out.Content, `operation="`+op+`"`) {
			t.Errorf("help topic analyze/%s has no section with a call example", op)
		}
		if !strings.Contains(index.Content, op) {
			t.Errorf("analyze help index does not list %s", op)
		}
	}
}
