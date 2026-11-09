package directoryalias

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sftptool "agent-tool/tools/sftp"
	"agent-tool/tools/ssh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Opt-in only: credentials stay in the ignored connection profile. All remote
// writes are confined to one verified mktemp directory, removed on completion.
func TestLivePOSIXDirectoryAliases(t *testing.T) {
	profile := os.Getenv("AGENT_TOOL_LIVE_SSH_PROFILE")
	if profile == "" {
		t.Skip("set AGENT_TOOL_LIVE_SSH_PROFILE for an authorized POSIX target")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "live-review", Version: "test"}, nil)
	req, _ := testSession(t, server)
	result, created, err := ssh.Handle(ctx, req, ssh.SSHInput{ConnectionProfile: profile, Command: "mktemp -d /tmp/agenttool-alias-review.XXXXXXXX", Quiet: true, ResultOnly: true, TimeoutSec: 15})
	if err != nil || result.IsError {
		t.Fatal("live scratch directory setup failed")
	}
	remote := strings.TrimSpace(created.Stdout)
	if !strings.HasPrefix(remote, "/tmp/agenttool-alias-review.") || strings.Count(remote, "/") != 2 || strings.ContainsAny(remote, "'\r\n") {
		t.Fatal("unsafe scratch directory response")
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		result, _, err := sftptool.Handle(cleanupCtx, req, sftptool.SFTPInput{ConnectionID: created.ConnectionID, Operation: "rm", RemotePath: remote, Recursive: true, Quiet: true, ResultOnly: true})
		if err != nil || result.IsError {
			t.Error("live scratch directory cleanup failed")
		}
	}()
	local := t.TempDir()
	body := "alias live roundtrip\nliteral @deploy/value\n"
	if err := os.WriteFile(filepath.Join(local, "source.txt"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []Input{{Operation: "set", Aliases: map[string]string{"local": local}}, {Operation: "set", ConnectionID: created.ConnectionID, Aliases: map[string]string{"deploy": remote}}} {
		result, _, err := Handle(ctx, req, input)
		if err != nil || result.IsError {
			t.Fatal("live alias registration failed")
		}
	}
	result, rooted, err := ssh.Handle(ctx, req, ssh.SSHInput{ConnectionID: created.ConnectionID, RemoteRoot: "@deploy", Command: "pwd; printf '%s' '@deploy/literal'", Quiet: true, ResultOnly: true, TimeoutSec: 15})
	if err != nil || result.IsError || !strings.HasPrefix(rooted.Stdout, remote+"\n") || !strings.Contains(rooted.Stdout, "@deploy/literal") {
		t.Fatal("live root or unchanged command check failed")
	}
	result, _, err = sftptool.Handle(ctx, req, sftptool.SFTPInput{ConnectionID: rooted.ConnectionID, Operation: "upload", LocalPath: "@local/source.txt", RemotePath: "@deploy/probe.txt", Quiet: true, ResultOnly: true})
	if err != nil || result.IsError {
		t.Fatal("live SFTP alias upload failed")
	}
	result, _, err = sftptool.Handle(ctx, req, sftptool.SFTPInput{ConnectionID: rooted.ConnectionID, Operation: "download", LocalPath: "@local/download.txt", RemotePath: "@deploy/probe.txt", Quiet: true, ResultOnly: true})
	if err != nil || result.IsError {
		t.Fatal("live SFTP alias download failed")
	}
	downloaded, err := os.ReadFile(filepath.Join(local, "download.txt"))
	if err != nil || string(downloaded) != body {
		t.Fatal("live SFTP roundtrip content changed")
	}
	// Fail before I/O, including when aliases are used through the SFTP handler.
	result, _, err = sftptool.Handle(ctx, req, sftptool.SFTPInput{ConnectionID: rooted.ConnectionID, Operation: "stat", RemotePath: "@deploy/../outside", Quiet: true, ResultOnly: true})
	if err != nil || !result.IsError {
		t.Fatal("live alias traversal was accepted")
	}
	// Explicit SSH background jobs must enforce the same owner through both
	// the result text and the structured SSH output.
	result, started, err := ssh.Handle(ctx, req, ssh.SSHInput{ConnectionID: rooted.ConnectionID, Operation: "start", Command: "printf BACKGROUND_ROOT_OK", Quiet: true, TimeoutSec: 15})
	if err != nil || result.IsError || started.JobID == "" {
		t.Fatal("live background start failed")
	}
	foreign, _ := testSession(t, server)
	result, hidden, err := ssh.Handle(ctx, foreign, ssh.SSHInput{Operation: "status", JobID: started.JobID})
	if err != nil || !result.IsError || hidden.JobID != "" || hidden.Stdout != "" {
		t.Fatal("foreign SSH job metadata was exposed")
	}
	result, completed, err := ssh.Handle(ctx, req, ssh.SSHInput{Operation: "wait", JobID: started.JobID, WaitSec: 5})
	if err != nil || result.IsError || !strings.Contains(completed.Result, "BACKGROUND_ROOT_OK") {
		t.Fatal("live background owner wait failed")
	}
}
