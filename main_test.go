package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-tool/tools/ssh"
	"agent-tool/tools/toolbox"

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
	return connectTestServer(t, server)
}

func connectTestServer(t *testing.T, server *mcp.Server) *mcp.ClientSession {
	t.Helper()
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

func TestProfileSearchThroughCoreLiteToolbox(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connections.json")
	t.Setenv("AGENT_TOOL_CONNECTION_PROFILE_FILE", path)
	data := `{"profiles":{
		" uncallable":{"host":"example.invalid"},
		"legacy":{"host":"example.invalid","user":"example","tags":false},
		"Archive":{"host":"example.invalid","user":"example","description":"Daily 백업","aliases":["copy"],"tags":["prod"],"password":"private-pass","key_file":"private-file","jump_passphrase":"private-jump"},
		"copy":{"tags":["prod"]},
		"other":{"aliases":["copy"],"tags":["prod"]}
	}}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "agent-tool", Version: "test"}, nil)
	manager := toolbox.NewManager(server, toolSpecs(server), Version)
	if err := manager.EnableProfile("core-lite"); err != nil {
		t.Fatal(err)
	}
	manager.RegisterTool()
	peer := connectTestServer(t, server)

	call := func(operation string, arguments map[string]any) *mcp.CallToolResult {
		t.Helper()
		params := map[string]any{"operation": operation, "tool": "profile_search"}
		if arguments != nil {
			params["arguments"] = arguments
		}
		result, err := peer.CallTool(t.Context(), &mcp.CallToolParams{Name: "toolbox", Arguments: params})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	describe := call("describe", nil)
	if describe.IsError || !strings.Contains(describe.Content[0].(*mcp.TextContent).Text, `"query"`) {
		t.Fatalf("profile search schema unavailable: %+v", describe)
	}
	check := func(args map[string]any, names string, total, next int) {
		t.Helper()
		result := call("call", args)
		raw, err := json.Marshal(result)
		if err != nil || result.IsError || strings.Contains(string(raw), "private-") {
			t.Fatalf("unexpected profile search result: %s (%v)", raw, err)
		}
		raw = []byte(result.Content[0].(*mcp.TextContent).Text)
		var output struct {
			Profiles []struct {
				Name string `json:"connection_profile"`
			} `json:"profiles"`
			Total int `json:"total"`
			Next  int `json:"next_offset"`
		}
		if err := json.Unmarshal(raw, &output); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, profile := range output.Profiles {
			got = append(got, profile.Name)
		}
		if output.Profiles == nil || strings.Join(got, ",") != names || output.Total != total || output.Next != next {
			t.Fatalf("unexpected profile page: %s", raw)
		}
	}
	check(map[string]any{"query": "COPY", "limit": 1}, "copy", 3, 1)
	check(map[string]any{"query": "copy", "offset": 1}, "Archive,other", 3, 0)
	check(map[string]any{"query": "백업 PROD"}, "Archive", 1, 0)
	connection := ssh.SSHInput{ConnectionProfile: "Archive"}
	if _, err := ssh.ResolveConnection(&connection); err != nil || connection.Host != "example.invalid" {
		t.Fatalf("search result did not resolve to the configured connection: %v", err)
	}
	check(nil, "Archive,copy,legacy,other", 4, 0)
	check(map[string]any{"query": "private"}, "", 0, 0)
	if result := call("call", map[string]any{"offset": -1}); !result.IsError {
		t.Fatal("negative offset succeeded")
	}
	long := strings.Repeat("x", 20*1024)
	data = `{"connections":{"first":{"description":"` + long + `"},"second":{"description":"` + long + `"}}}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	check(nil, "first", 2, 1)
	check(map[string]any{"offset": 1}, "second", 2, 0)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	result := call("call", nil)
	if !result.IsError || strings.Contains(result.Content[0].(*mcp.TextContent).Text, path) {
		t.Fatal("missing configured file must give a path-free tool error")
	}
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
