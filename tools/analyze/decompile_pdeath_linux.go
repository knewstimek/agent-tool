//go:build linux

package analyze

import "syscall"

// setParentDeathSignal has the kernel SIGKILL the worker when the server
// exits, even if the server is killed without running any cleanup.
func setParentDeathSignal(attr *syscall.SysProcAttr) { attr.Pdeathsig = syscall.SIGKILL }
