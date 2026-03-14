//go:build windows

package procexec

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	_CREATE_SUSPENDED = 0x00000004
)

// startSuspended starts a process in suspended state using CreateProcess with CREATE_SUSPENDED.
func startSuspended(command string, args []string, cwd string, env []string) (int, error) {
	cmdLine, err := buildCommandLine(command, args)
	if err != nil {
		return 0, err
	}

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	cmdLinePtr, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		return 0, fmt.Errorf("invalid command line: %w", err)
	}

	var cwdPtr *uint16
	if cwd != "" {
		cwdPtr, err = syscall.UTF16PtrFromString(cwd)
		if err != nil {
			return 0, fmt.Errorf("invalid working directory: %w", err)
		}
	}

	var envBlock *uint16
	var envSlice []uint16 // keep reference to prevent GC
	if len(env) > 0 {
		envSlice = createEnvBlock(mergeEnv(env))
		if len(envSlice) > 0 {
			envBlock = &envSlice[0]
		}
	}

	createErr := windows.CreateProcess(
		nil, // lpApplicationName — let the system resolve via cmdLine
		cmdLinePtr,
		nil, nil, // process and thread security attributes
		false,             // inherit handles
		_CREATE_SUSPENDED, // creation flags
		envBlock,
		cwdPtr,
		&si, &pi,
	)
	runtime.KeepAlive(envSlice) // prevent GC before CreateProcess completes

	if createErr != nil {
		return 0, fmt.Errorf("CreateProcess: %w", createErr)
	}

	pid := int(pi.ProcessId)
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)

	return pid, nil
}

// buildCommandLine constructs a proper Windows command line string.
func buildCommandLine(command string, args []string) (string, error) {
	// Resolve command path
	resolved, err := exec.LookPath(command)
	if err != nil {
		// Use as-is if LookPath fails (might be a full path)
		resolved = command
	}

	parts := make([]string, 0, 1+len(args))
	parts = append(parts, syscall.EscapeArg(resolved))
	for _, arg := range args {
		parts = append(parts, syscall.EscapeArg(arg))
	}

	return strings.Join(parts, " "), nil
}

// createEnvBlock creates a null-terminated UTF-16 environment block for CreateProcess.
// Each entry is null-separated, with a double null at the end.
// Returns the backing slice to prevent GC; caller must keep a reference.
func createEnvBlock(env []string) []uint16 {
	if len(env) == 0 {
		return nil
	}

	// Convert each entry individually to preserve internal null separators
	var buf []uint16
	for _, e := range env {
		// Encode entry to UTF-16 (without null terminator from UTF16FromString)
		runes := []rune(e)
		encoded := utf16.Encode(runes)
		buf = append(buf, encoded...)
		buf = append(buf, 0) // null separator between entries
	}
	buf = append(buf, 0) // double null terminator

	return buf
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

	if err := cmd.Start(); err != nil {
		return 0, err
	}

	pid := cmd.Process.Pid
	cmd.Process.Release()

	return pid, nil
}

// resolvePath attempts to find the command in PATH.
func resolvePath(command string) string {
	if path, err := exec.LookPath(command); err == nil {
		return path
	}
	return command
}
