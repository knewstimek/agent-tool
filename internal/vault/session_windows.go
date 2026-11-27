package vault

import (
	"context"
	"net"
	"os"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func localDataDir() string { return os.Getenv("LOCALAPPDATA") }

func pipePath(id string) (string, string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", "", err
	}
	sid := user.User.Sid.String()
	return `\\.\pipe\agent-tool-vault-` + sid + "-" + id, sid, nil
}

func listenSession(id string) (net.Listener, error) {
	path, sid, err := pipePath(id)
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + sid + ")"})
}

func dialSession(ctx context.Context, id string) (net.Conn, error) {
	path, _, err := pipePath(id)
	if err != nil {
		return nil, err
	}
	return winio.DialPipeContext(ctx, path)
}

func openTerminal() (*os.File, error) { return os.OpenFile("CONIN$", os.O_RDWR, 0) }
