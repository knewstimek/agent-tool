package sftp

import (
	"agent-tool/common"
	"agent-tool/tools/ssh"
)

func (input SFTPInput) displayLocal() string {
	return common.DisplayPathWithAliases(input.localRoot, input.LocalPath, input.localAliases)
}

func (input SFTPInput) displayRemote(p string) string {
	return ssh.DisplayRemotePathWithAliases(input.RemoteRoot, p, input.remoteAliases)
}

func (input *SFTPInput) resolveRemotePaths() error {
	resolve := func(p string) (string, error) {
		expanded, err := common.ExpandDirectoryAlias(input.remoteAliases, p, ssh.ResolveRemotePath)
		if err != nil {
			return "", err
		}
		return ssh.ResolveRemotePath(input.RemoteRoot, expanded), nil
	}
	var err error
	input.RemotePath, err = resolve(input.RemotePath)
	if err != nil {
		return err
	}
	input.NewPath, err = resolve(input.NewPath)
	if err != nil {
		return err
	}
	for i := range input.Uploads {
		input.Uploads[i].RemotePath, err = resolve(input.Uploads[i].RemotePath)
		if err != nil {
			return err
		}
	}
	return nil
}
