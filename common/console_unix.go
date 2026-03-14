//go:build !windows

package common

// DecodeConsoleOutput은 Unix에서는 변환 없이 그대로 반환한다.
// Unix 터미널은 일반적으로 UTF-8을 사용한다.
func DecodeConsoleOutput(data []byte) string {
	return string(data)
}

// SystemCodePageInfo는 Unix에서 코드페이지 정보를 반환한다.
func SystemCodePageInfo() string {
	return "UTF-8 (Unix default)"
}
