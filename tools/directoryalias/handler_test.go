package directoryalias

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-tool/common"
	copytool "agent-tool/tools/copy"
	"agent-tool/tools/edit"
	"agent-tool/tools/multiread"
	"agent-tool/tools/read"
	"agent-tool/tools/ssh"
	"agent-tool/tools/toolbox"
	"agent-tool/tools/write"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func testSession(t *testing.T, server *mcp.Server) (*mcp.CallToolRequest, *mcp.ClientSession) {
	t.Helper()
	a, b := mcp.NewInMemoryTransports()
	session, err := server.Connect(t.Context(), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	peer, err := client.Connect(t.Context(), b, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close(); _ = session.Close(); _ = session.Wait() })
	return &mcp.CallToolRequest{Session: session}, peer
}

func textOf(t *testing.T, r *mcp.CallToolResult) string {
	t.Helper()
	return r.Content[0].(*mcp.TextContent).Text
}

func TestAliasMCPWorkflowAndSessionIsolation(t *testing.T) {
	root := t.TempDir()
	old := common.GetWorkspace()
	common.SetWorkspace(root)
	t.Cleanup(func() { common.SetWorkspace(old) })
	src := filepath.Join(root, "very", "deep", "source", "directory")
	dst := filepath.Join(root, "very", "deep", "destination", "directory")
	for _, p := range []string{src, dst} {
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	Register(server)
	read.Register(server)
	write.Register(server)
	edit.Register(server)
	copytool.Register(server)
	multiread.Register(server)
	manager := toolbox.NewManager(server, []toolbox.Spec{{Name: "directory_alias", Group: "file", Register: func() { Register(server) }}})
	manager.RegisterTool()
	req, peer := testSession(t, server)
	_, other := testSession(t, server)
	call := func(session *mcp.ClientSession, name string, args map[string]any, wantError bool) string {
		t.Helper()
		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil || result.IsError != wantError {
			t.Fatalf("%s: result=%+v err=%v", name, result, err)
		}
		return textOf(t, result)
	}
	result := call(peer, "directory_alias", map[string]any{"operation": "set", "aliases": map[string]string{"src": src, "dst": dst}}, false)
	if result != "OK" {
		t.Fatalf("registration echoed paths: %s", result)
	}
	call(peer, "toolbox", map[string]any{"operation": "describe", "tool": "directory_alias", "compact": true}, false)
	result = call(peer, "toolbox", map[string]any{"operation": "call", "tool": "directory_alias", "arguments": map[string]any{"operation": "list", "names": []string{"src"}}}, false)
	if !strings.Contains(result, "src") {
		t.Fatal("gateway lost alias session")
	}
	body := "original @src/literal " + src
	result = call(peer, "write", map[string]any{"file_path": "@src/file.txt", "content": body}, false)
	if !strings.Contains(result, "@src/file.txt") {
		t.Fatal(result)
	}
	call(peer, "edit", map[string]any{"file_path": "@src/file.txt", "old_string": "original", "new_string": "changed"}, false)
	call(peer, "copy", map[string]any{"source": "@src/file.txt", "destination": "@dst/copy.txt"}, false)
	result = call(peer, "read", map[string]any{"file_path": "@dst/copy.txt"}, false)
	if !strings.Contains(result, "changed @src/literal "+src) {
		t.Fatal("file body was rewritten")
	}
	result = call(peer, "multiread", map[string]any{"file_paths": []string{"@src/file.txt", "@dst/copy.txt"}}, false)
	if !strings.Contains(result, "=== @src/file.txt ===") || !strings.Contains(result, "=== @dst/copy.txt ===") {
		t.Fatal(result)
	}
	call(other, "read", map[string]any{"file_path": "@src/file.txt"}, true)
	for _, p := range []string{"@missing/file", "@src/../escape", "@src//absolute", "@src/C:/escape", "@src/file:stream"} {
		call(peer, "write", map[string]any{"file_path": p, "content": "bad"}, true)
	}
	call(peer, "directory_alias", map[string]any{"operation": "set", "aliases": map[string]string{"src": dst}}, true)
	if got, err := common.ResolveRequestPath(t.Context(), req, "@src/file.txt"); err != nil || got != filepath.Join(src, "file.txt") {
		t.Fatalf("binding changed: %q %v", got, err)
	}
	snapshot := common.DirectoryAliasMap(t.Context(), req, common.LocalAliasScope(t.Context(), req))
	snapshot["src"] = dst
	if got, _ := common.ResolveRequestPath(t.Context(), req, "@src/file.txt"); got != filepath.Join(src, "file.txt") {
		t.Fatal("snapshot mutated registry")
	}
	call(peer, "directory_alias", map[string]any{"operation": "delete", "names": []string{"src", "absent"}}, true)
	call(peer, "read", map[string]any{"file_path": "@src/file.txt"}, false)
	call(peer, "directory_alias", map[string]any{"operation": "delete", "names": []string{"src"}}, false)
	call(peer, "read", map[string]any{"file_path": "@src/file.txt"}, true)
}

func TestRemoteAliasConnectionIdentityAndUnchangedCommand(t *testing.T) {
	root := t.TempDir()
	profiles := filepath.Join(root, "connections.json")
	data := map[string]any{"connections": map[string]any{"a": map[string]any{"host": "a.example.invalid", "user": "builder", "remote_root": "/srv/app"}, "b": map[string]any{"host": "b.example.invalid", "user": "builder", "remote_root": "/srv/app"}}}
	data["connections"].(map[string]any)["c"] = map[string]any{"host": "c.example.invalid", "user": "builder", "remote_root": "@deploy"}
	encoded, _ := json.Marshal(data)
	if err := os.WriteFile(profiles, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_TOOL_CONNECTION_PROFILE_FILE", profiles)
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	Register(server)
	req, _ := testSession(t, server)
	second, _ := testSession(t, server)
	result, _, err := Handle(t.Context(), req, Input{Operation: "set", ConnectionProfile: "a", Aliases: map[string]string{"deploy": "/opt/releases/current"}})
	if err != nil || result.IsError {
		t.Fatalf("set: %v %+v", err, result)
	}
	input := ssh.SSHInput{ConnectionProfile: "a", RemoteRoot: "@deploy/subdir", Command: "echo @deploy/not-a-path-argument"}
	id, err := ssh.ResolveConnectionForRequest(t.Context(), req, &input)
	if err != nil || input.RemoteRoot != "/opt/releases/current/subdir" || input.Command != "echo @deploy/not-a-path-argument" {
		t.Fatalf("remote resolution: %+v %v", input, err)
	}
	reused := ssh.SSHInput{ConnectionID: id}
	if _, err := ssh.ResolveConnectionForRequest(context.Background(), req, &reused); err != nil || reused.RemoteRoot != input.RemoteRoot {
		t.Fatalf("reused root: %+v %v", reused, err)
	}
	for _, tt := range []struct {
		request *mcp.CallToolRequest
		profile string
	}{{req, "b"}, {second, "a"}} {
		foreign := ssh.SSHInput{ConnectionProfile: tt.profile, RemoteRoot: "@deploy"}
		if _, err := ssh.ResolveConnectionForRequest(t.Context(), tt.request, &foreign); err == nil {
			t.Fatal("remote alias crossed session or host")
		}
	}
	// Changing cwd must not change the alias namespace for the same target.
	scope := ssh.ConnectionAliasScope(input)
	if common.DirectoryAliasMap(t.Context(), req, scope)["deploy"] != "/opt/releases/current" {
		t.Fatal("root change lost aliases")
	}
	result, _, err = Handle(t.Context(), req, Input{Operation: "set", ConnectionProfile: "c", Aliases: map[string]string{"deploy": "/srv/third"}})
	if err != nil || result.IsError {
		t.Fatalf("profile root registration cycle: %v %+v", err, result)
	}
	third := ssh.SSHInput{ConnectionProfile: "c"}
	if _, err := ssh.ResolveConnectionForRequest(t.Context(), req, &third); err != nil || third.RemoteRoot != "/srv/third" {
		t.Fatalf("profile root alias: %+v %v", third, err)
	}
}
