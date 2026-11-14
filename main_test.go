package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tool descriptions, parameter descriptions and help cost tokens on every
// session or call, so they hold only what changes the agent's next call. How
// the tool is built is not written there (nor moved to the README). These
// tests hold that line: a size budget and a few giveaway phrases.

const (
	toolDescriptionMax  = 1500
	paramDescriptionMax = 600
)

var implementationProse = []string{
	"powered by", "pure go", "no cgo", "zero token", "wazero", "tree-sitter",
	"under the hood", "blazing",
}

func proseHits(text string) []string {
	lower := strings.ToLower(text)
	var hits []string
	for _, phrase := range implementationProse {
		if strings.Contains(lower, phrase) {
			hits = append(hits, phrase)
		}
	}
	return hits
}

func fullSession(t *testing.T) *mcp.ClientSession {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "agent-tool", Version: "test"}, nil)
	for _, spec := range toolSpecs(server) {
		spec.Register()
	}
	a, b := mcp.NewInMemoryTransports()
	session, err := server.Connect(t.Context(), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(t.Context(), b, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close(); _ = session.Close(); _ = session.Wait() })
	return peer
}

func TestToolDescriptionsStayActionable(t *testing.T) {
	tools, err := fullSession(t).ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) < 30 {
		t.Fatalf("only %d tools registered", len(tools.Tools))
	}
	for _, tool := range tools.Tools {
		if n := len(tool.Description); n > toolDescriptionMax {
			t.Errorf("%s: description is %d chars (max %d); move usage detail to agent_tool_help and delete the rest", tool.Name, n, toolDescriptionMax)
		}
		if hits := proseHits(tool.Description); len(hits) > 0 {
			t.Errorf("%s: description has implementation prose %q; say what the agent can do with the tool instead", tool.Name, hits)
		}
		raw, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties map[string]struct {
				Description string `json:"description"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("%s: input schema: %v", tool.Name, err)
		}
		for name, p := range schema.Properties {
			if n := len(p.Description); n > paramDescriptionMax {
				t.Errorf("%s.%s: description is %d chars (max %d)", tool.Name, name, n, paramDescriptionMax)
			}
			if hits := proseHits(p.Description); len(hits) > 0 {
				t.Errorf("%s.%s: description has implementation prose %q", tool.Name, name, hits)
			}
		}
	}
}

// helpText reads one help answer through the tool, as an agent does.
func helpText(t *testing.T, peer *mcp.ClientSession, topic string) string {
	t.Helper()
	res, err := peer.CallTool(t.Context(), &mcp.CallToolParams{Name: "agent_tool_help", Arguments: map[string]any{"topic": topic}})
	if err != nil {
		t.Fatalf("agent_tool_help %q: %v", topic, err)
	}
	return res.Content[0].(*mcp.TextContent).Text
}

// listAfter returns the comma-separated names that follow marker in text.
func listAfter(text, marker string) []string {
	_, rest, ok := strings.Cut(text, marker)
	if !ok {
		return nil
	}
	rest, _, _ = strings.Cut(rest, "\n")
	var names []string
	for _, name := range strings.Split(rest, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func TestHelpStaysActionable(t *testing.T) {
	peer := fullSession(t)
	topics := listAfter(helpText(t, peer, "no-such-topic"), "Available topics: ")
	if len(topics) < 8 {
		t.Fatalf("could not list help topics: %v", topics)
	}
	for _, topic := range topics {
		text := helpText(t, peer, topic)
		// An indexed topic answers with its index; its sections are read in
		// full by asking for all of them.
		if sections := listAfter(helpText(t, peer, topic+"/no-such-section"), "Available: "); len(sections) > 0 {
			text += "\n" + helpText(t, peer, topic+"/"+strings.Join(sections, ","))
		}
		if hits := proseHits(text); len(hits) > 0 {
			t.Errorf("help topic %s has implementation prose %q; keep what changes the agent's next call and delete the rest", topic, hits)
		}
		for i := 0; i < len(text); i++ {
			if text[i] > 127 {
				t.Errorf("help topic %s has non-ASCII text near %q", topic, text[max(0, i-20):min(len(text), i+20)])
				break
			}
		}
	}
}
