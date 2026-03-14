//go:build !windows

package common

// DecodeConsoleOutput returns the data as-is on Unix without conversion.
// Unix terminals typically use UTF-8.
func DecodeConsoleOutput(data []byte) string {
	return string(data)
}

// SystemCodePageInfo returns code page information on Unix.
func SystemCodePageInfo() string {
	return "UTF-8 (Unix default)"
}
