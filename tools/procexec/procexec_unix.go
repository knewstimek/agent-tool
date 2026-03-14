//go:build !windows

package procexec

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// startSuspended starts a process and immediately sends SIGSTOP.
func startSuspended(command string, args []string, cwd string, env []string) (int, error) {
	cmd := exec.Command(command, args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	if len(env) > 0 {
		cmd.Env = mergeEnv(env)
	}

	// Detach from parent's stdout/stderr
	cmd.Stdout = nil
	cmd.Stderr = nil

	// Set process group so the child doesn't receive our signals
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start process: %w", err)
	}

	pid := cmd.Process.Pid

	// Send SIGSTOP immediately
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		// If SIGSTOP fails, kill the process to avoid leaving it running
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 0, fmt.Errorf("failed to suspend process %d: %w", pid, err)
	}

	// Release the process so we don't become a zombie parent
	cmd.Process.Release()

	return pid, nil
}

// startBackground starts a process in the background.
func startBackground(command string, args []string, cwd string, env []string) (int, error) {
	cmd := exec.Command(command, args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	if len(env) > 0 {
		cmd.Env = mergeEnv(env)
	}

	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return 0, err
	}

	pid := cmd.Process.Pid
	cmd.Process.Release()

	return pid, nil
}

// resolvePath attempts to find the command in PATH if it's not an absolute path.
func resolvePath(command string) string {
	if path, err := exec.LookPath(command); err == nil {
		return path
	}
	return command
}

// isExecutable checks if a file is executable.
func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&0111 != 0
}
