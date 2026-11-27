//go:build !windows

package vault

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func localDataDir() string { return "" }

func sessionPath(id string) string {
	return filepath.Join("/tmp", fmt.Sprintf("agent-tool-vault-%d", os.Getuid()), id)
}

type sessionListener struct {
	net.Listener
	lock *os.File
}

func (l *sessionListener) Close() error {
	err := l.Listener.Close()
	_ = l.lock.Close()
	return err
}

func listenSession(id string) (net.Listener, error) {
	path := sessionPath(id)
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return nil, fmt.Errorf("unsafe vault session directory")
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("this vault is already unlocked")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		lock.Close()
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		lock.Close()
		return nil, err
	}
	return &sessionListener{listener, lock}, nil
}

func dialSession(ctx context.Context, id string) (net.Conn, error) {
	path := sessionPath(id)
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return nil, fmt.Errorf("vault session unavailable")
	}
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}

func openTerminal() (*os.File, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }
