package sftp

import (
	"agent-tool/common"
	"agent-tool/tools/ssh"
)

func (input SFTPInput) displayLocal() string {
	return common.DisplayPath(input.localRoot, input.LocalPath)
}

func (input SFTPInput) displayRemote(p string) string {
	return ssh.DisplayRemotePath(input.RemoteRoot, p)
}

func (input *SFTPInput) resolveRemotePaths() {
	input.RemotePath = ssh.ResolveRemotePath(input.RemoteRoot, input.RemotePath)
	input.NewPath = ssh.ResolveRemotePath(input.RemoteRoot, input.NewPath)
	for i := range input.Uploads {
		input.Uploads[i].RemotePath = ssh.ResolveRemotePath(input.RemoteRoot, input.Uploads[i].RemotePath)
	}
}
