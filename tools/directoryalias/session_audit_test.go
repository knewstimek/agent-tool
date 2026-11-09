package directoryalias

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"agent-tool/common"
	"agent-tool/tools/bash"
	"agent-tool/tools/ssh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestConnectionHandlesStayInTheirMCPSession(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "audit", Version: "test"}, nil)
	owner, _ := testSession(t, server)
	other, _ := testSession(t, server)
	first := ssh.SSHInput{Host: "example.invalid", User: "builder", RemoteRoot: "/srv/project"}
	id, err := ssh.ResolveConnectionForRequest(t.Context(), owner, &first)
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []*mcp.CallToolRequest{other, nil} {
		foreign := ssh.SSHInput{ConnectionID: id}
		if _, err := ssh.ResolveConnectionForRequest(t.Context(), req, &foreign); err == nil || foreign.Host != "" {
			t.Error("foreign session resolved connection credentials")
		}
	}
	r, _, err := Handle(t.Context(), other, Input{Operation: "set", ConnectionID: id, Aliases: map[string]string{"deploy": "/srv/other"}})
	if err != nil || !r.IsError {
		t.Fatal("alias management accepted a foreign connection handle")
	}
	second := ssh.SSHInput{Host: "example.invalid", User: "builder", RemoteRoot: "/srv/project"}
	secondID, err := ssh.ResolveConnectionForRequest(t.Context(), other, &second)
	if err != nil || secondID == id {
		t.Fatal("connection handle deduplication crossed sessions")
	}
	ctx := common.WithToolRequest(context.Background(), owner)
	for _, req := range []*mcp.CallToolRequest{owner, nil} {
		reuse := ssh.SSHInput{ConnectionID: id}
		if got, err := ssh.ResolveConnectionForRequest(ctx, req, &reuse); err != nil || got != id || reuse.RemoteRoot != first.RemoteRoot {
			t.Fatal("owning session could not reuse its handle")
		}
	}
}

func TestBashAliasCWDAndDisconnectStayInTheirMCPSession(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "audit", Version: "test"}, nil)
	owner, _ := testSession(t, server)
	other, _ := testSession(t, server)
	for i, req := range []*mcp.CallToolRequest{owner, other} {
		dir := filepath.Join(t.TempDir(), "workspace")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		r, _, err := Handle(t.Context(), req, Input{Operation: "set", Aliases: map[string]string{"work": dir}})
		if err != nil || r.IsError {
			t.Fatal("alias setup failed")
		}
		t.Cleanup(func() { _, _, _ = bash.Handle(context.Background(), req, bash.BashInput{Disconnect: true}) })
		r, out, err := bash.Handle(t.Context(), req, bash.BashInput{Cwd: "@work", Command: "echo SHELL_READY > created.txt", TimeoutSec: 10})
		if err != nil || r.IsError || !out.IsNew {
			t.Fatalf("client %d reused another client's default shell: output=%+v err=%v", i, out, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "created.txt")); err != nil {
			t.Fatal("shell did not use its own alias directory")
		}
	}
	_, _, _ = bash.Handle(t.Context(), other, bash.BashInput{Disconnect: true})
	r, out, err := bash.Handle(t.Context(), owner, bash.BashInput{Command: "echo STILL_OWNED", TimeoutSec: 10})
	if err != nil || r.IsError || out.IsNew {
		t.Fatal("foreign disconnect closed the owner's shell")
	}
}
