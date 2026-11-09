package sftp

import (
	"testing"
)

func TestRemoteAliasPathsBatchRenameAndDisplay(t *testing.T) {
	for _, base := range []string{"/opt/deep/releases/current", "D:/deep/releases/current"} {
		input := SFTPInput{RemoteRoot: "/srv/app", RemotePath: "@deploy/a.txt", NewPath: "@deploy/b.txt", remoteAliases: map[string]string{"deploy": base}, Uploads: []UploadItem{{RemotePath: "@deploy/c.txt"}}}
		if err := input.resolveRemotePaths(); err != nil {
			t.Fatal(err)
		}
		if input.RemotePath != base+"/a.txt" || input.NewPath != base+"/b.txt" || input.Uploads[0].RemotePath != base+"/c.txt" {
			t.Fatalf("%+v", input)
		}
		if input.displayRemote(input.RemotePath) != "@deploy/a.txt" {
			t.Fatal(input.displayRemote(input.RemotePath))
		}
	}
	for _, p := range []string{"@missing/a", "@deploy/../escape", "@deploy//escape", "@deploy/C:/escape"} {
		input := SFTPInput{RemotePath: p, remoteAliases: map[string]string{"deploy": "/opt/app"}}
		if err := input.resolveRemotePaths(); err == nil {
			t.Fatalf("accepted %q", p)
		}
	}
}
