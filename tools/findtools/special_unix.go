//go:build !windows

package findtools

// discoverMSVC is not applicable on Unix.
func discoverMSVC() ToolInfo {
	return ToolInfo{Name: "cl (MSVC)"}
}

// discoverPyLauncher is not applicable on Unix (python3 is the default).
func discoverPyLauncher() ToolInfo {
	return ToolInfo{Name: "py (launcher)"}
}
