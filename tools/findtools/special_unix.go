//go:build !windows

package findtools

// discoverMSVC는 Unix에서는 해당 없음.
func discoverMSVC() ToolInfo {
	return ToolInfo{Name: "cl (MSVC)"}
}

// discoverPyLauncher는 Unix에서는 해당 없음 (python3가 기본).
func discoverPyLauncher() ToolInfo {
	return ToolInfo{Name: "py (launcher)"}
}
