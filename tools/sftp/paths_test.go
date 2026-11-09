package sftp

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-tool/tools/ssh"
	gosftp "github.com/pkg/sftp"
)

func TestRemoteRootSharedHandleAndSFTPOperations(t *testing.T) {
	first := ssh.SSHInput{Host: "example.invalid", User: "builder", RemoteRoot: "/srv/app"}
	id, err := ssh.ResolveConnection(&first)
	if err != nil {
		t.Fatal(err)
	}
	input := SFTPInput{ConnectionID: id, localRoot: t.TempDir(), RemotePath: "config.txt"}
	resolved := toSSHInput(input)
	if _, err := ssh.ResolveConnection(&resolved); err != nil {
		t.Fatal(err)
	}
	applyResolvedConnection(&input, resolved)
	input.resolveRemotePaths()
	if input.RemotePath != "/srv/app/config.txt" || input.RemoteShell != "posix" {
		t.Fatalf("shared root not applied: %+v", input)
	}
	input.LocalPath = filepath.Join(input.localRoot, "source.txt")
	body := "literal /srv/app/unchanged " + input.localRoot
	if err := os.WriteFile(input.LocalPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	serverConn, clientConn := net.Pipe()
	server := gosftp.NewRequestServer(serverConn, gosftp.InMemHandler())
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(); _ = server.Close() }()
	client, err := gosftp.NewClientPipe(clientConn, clientConn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = clientConn.Close(); _ = serverConn.Close(); <-done })
	if err := client.MkdirAll(input.RemoteRoot); err != nil {
		t.Fatal(err)
	}
	result, err := opUpload(client, input)
	if err != nil || !strings.Contains(result, "source.txt -> config.txt") || strings.Contains(result, input.localRoot) || strings.Contains(result, input.RemoteRoot) {
		t.Fatalf("upload: %s %v", result, err)
	}
	f, err := client.Open(input.RemotePath)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || string(data) != body {
		t.Fatalf("uploaded content changed: %q %v", data, err)
	}
	input.NewPath = "renamed.txt"
	input.resolveRemotePaths()
	result, err = opRename(client, input)
	if err != nil || result != "Renamed: config.txt -> renamed.txt" {
		t.Fatalf("rename: %s %v", result, err)
	}
	input.RemotePath = input.NewPath
	input.LocalPath = filepath.Join(input.localRoot, "downloaded.txt")
	result, err = opDownload(client, input)
	if err != nil || !strings.Contains(result, "renamed.txt -> downloaded.txt") {
		t.Fatalf("download: %s %v", result, err)
	}
	data, err = os.ReadFile(input.LocalPath)
	if err != nil || string(data) != body {
		t.Fatalf("downloaded content changed: %q %v", data, err)
	}
	input.RemotePath = "."
	input.resolveRemotePaths()
	result, err = opLs(client, input)
	if err != nil || !strings.HasPrefix(result, "Directory: . ") {
		t.Fatalf("ls: %s %v", result, err)
	}
	input.Uploads = []UploadItem{{LocalPath: input.LocalPath, RemotePath: "batch.txt"}}
	input.resolveRemotePaths()
	if input.Uploads[0].RemotePath != "/srv/app/batch.txt" {
		t.Fatal("batch root not applied")
	}
	result, count, err := opUploadMany(client, input)
	if err != nil || count != 1 || strings.Contains(result, input.RemoteRoot) || strings.Contains(result, input.localRoot) {
		t.Fatalf("batch: %s %d %v", result, count, err)
	}
	input.remoteAliases = map[string]string{"deploy": "/opt/deep/releases/current"}
	if err := client.MkdirAll(input.remoteAliases["deploy"]); err != nil {
		t.Fatal(err)
	}
	input.RemotePath = "@deploy/aliased.txt"
	if err := input.resolveRemotePaths(); err != nil {
		t.Fatal(err)
	}
	result, err = opUpload(client, input)
	if err != nil || !strings.Contains(result, "@deploy/aliased.txt") {
		t.Fatalf("aliased upload: %s %v", result, err)
	}
	if _, err := client.Stat("/opt/deep/releases/current/aliased.txt"); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteRootDriveDeletionGuard(t *testing.T) {
	for _, p := range []string{"C:/", `C:\`, "C:/app/.."} {
		if !isDangerousPath(p) {
			t.Errorf("unprotected drive root: %q", p)
		}
	}
}
