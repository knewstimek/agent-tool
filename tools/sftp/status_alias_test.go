package sftp

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestTransferStatusDoesNotReuseReboundAlias(t *testing.T) {
	root := t.TempDir()
	old := common.GetWorkspace()
	common.SetWorkspace(root)
	t.Cleanup(func() { common.SetWorkspace(old) })
	scope := "remote:status-regression"
	aliases := map[string]string{"deploy": "/opt/deep/old"}
	if err := common.UpdateDirectoryAliases(t.Context(), nil, scope, aliases, nil, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = common.UpdateDirectoryAliases(t.Context(), nil, scope, nil, []string{"deploy"}, false) })
	entry := &transferEntry{ID: "status-regression", LocalPath: filepath.Join(root, "local.txt"), RemotePath: "/opt/deep/old/file.txt", remoteAliasScope: scope, Status: "completed", StartedAt: time.Now(), CompletedAt: time.Now()}
	if got := formatTransferStatus(t.Context(), nil, entry); !strings.Contains(got, "Remote: @deploy/file.txt") {
		t.Fatal(got)
	}
	if err := common.UpdateDirectoryAliases(t.Context(), nil, scope, map[string]string{"deploy": "/opt/deep/new"}, nil, true); err != nil {
		t.Fatal(err)
	}
	got := formatTransferStatus(t.Context(), nil, entry)
	if strings.Contains(got, "@deploy") || !strings.Contains(got, "Remote: /opt/deep/old/file.txt") {
		t.Fatal("rebound alias redirected historical transfer path: " + got)
	}
}

func TestTransferStatusAndCancelAreSessionOwned(t *testing.T) {
	owner, other := &mcp.ServerSession{}, &mcp.ServerSession{}
	called := false
	entry := &transferEntry{ID: "session-owner-regression", session: owner, Status: "running", cancel: func() { called = true }}
	transfers.mu.Lock()
	transfers.m[entry.ID] = entry
	transfers.mu.Unlock()
	t.Cleanup(func() { transfers.mu.Lock(); delete(transfers.m, entry.ID); transfers.mu.Unlock() })
	if _, err := opStatus(t.Context(), nil, SFTPInput{TransferID: entry.ID, session: other}); err == nil {
		t.Fatal("foreign session read transfer")
	}
	all, err := opStatus(t.Context(), nil, SFTPInput{session: other})
	if err != nil || strings.Contains(all, entry.ID) {
		t.Fatal("foreign session listed transfer")
	}
	if _, err := opCancel(SFTPInput{TransferID: entry.ID, session: other}); err == nil || called {
		t.Fatal("foreign session canceled transfer")
	}
	if _, err := opCancel(SFTPInput{TransferID: entry.ID, session: owner}); err != nil || !called {
		t.Fatal("owner could not cancel transfer")
	}
}
