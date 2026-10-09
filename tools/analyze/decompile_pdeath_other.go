//go:build !windows && !linux

package analyze

import "syscall"

// No parent-death signal outside Linux; the worker's parent watch covers it.
func setParentDeathSignal(*syscall.SysProcAttr) {}
