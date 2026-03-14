package delete

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type DeleteInput struct {
	FilePath string `json:"file_path" jsonschema:"Absolute path to the file to delete"`
	DryRun   bool   `json:"dry_run" jsonschema:"Preview deletion without actually removing the file (default false)"`
}

type DeleteOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input DeleteInput) (*mcp.CallToolResult, DeleteOutput, error) {
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}

	// 경로 정규화
	cleaned := filepath.Clean(input.FilePath)

	// [FIX #4] 경로 구성요소 단위로 ".." 검사 (파일명 내 연속 점 오탐 방지)
	for _, part := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if part == ".." {
			return errorResult("path traversal (..) is not allowed")
		}
	}

	// [FIX #2] Windows 예약 장치 이름 차단
	if runtime.GOOS == "windows" {
		if err := checkWindowsReserved(cleaned); err != nil {
			return errorResult(err.Error())
		}
	}

	// [FIX #3] 시스템 중요 경로 차단
	if err := checkDangerousPath(cleaned); err != nil {
		return errorResult(err.Error())
	}

	// 파일 정보 확인
	info, err := os.Lstat(cleaned) // Lstat: 심볼릭 링크를 따라가지 않음
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", cleaned))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}

	// 디렉토리 삭제 금지
	if info.IsDir() {
		return errorResult("directory deletion is not allowed. Only individual files can be deleted")
	}

	// 심볼릭 링크 삭제 금지
	if info.Mode()&os.ModeSymlink != 0 {
		return errorResult("symlink deletion is not allowed for safety")
	}

	// dry_run 모드
	if input.DryRun {
		msg := fmt.Sprintf("[DRY RUN] would delete: %s (%d bytes)", cleaned, info.Size())
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, DeleteOutput{Result: msg}, nil
	}

	// [FIX #1] TOCTOU 완화: 삭제 직전 파일 상태 재확인
	info2, err := os.Lstat(cleaned)
	if err != nil {
		return errorResult(fmt.Sprintf("pre-delete check failed: %v", err))
	}
	if info2.IsDir() || info2.Mode()&os.ModeSymlink != 0 {
		return errorResult("file type changed before deletion (possible race condition)")
	}

	// 실제 삭제
	if err := os.Remove(cleaned); err != nil {
		return errorResult(fmt.Sprintf("delete failed: %v", err))
	}

	msg := fmt.Sprintf("OK: deleted %s (%d bytes)", cleaned, info.Size())
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, DeleteOutput{Result: msg}, nil
}

// checkWindowsReserved는 Windows 예약 장치 이름과 ADS 경로를 차단한다.
func checkWindowsReserved(cleaned string) error {
	// ADS (Alternate Data Stream) 차단: 드라이브 문자의 콜론 이후에 또 콜론이 있으면 ADS
	drive := filepath.VolumeName(cleaned)
	rest := cleaned[len(drive):]
	if strings.Contains(rest, ":") {
		return fmt.Errorf("alternate data stream (ADS) paths are not allowed")
	}

	// 예약 장치 이름 차단
	base := filepath.Base(cleaned)
	upperBase := strings.ToUpper(strings.TrimSuffix(base, filepath.Ext(base)))
	reserved := []string{
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
	}
	for _, r := range reserved {
		if upperBase == r {
			return fmt.Errorf("deletion of Windows reserved device name is not allowed: %s", base)
		}
	}
	return nil
}

// checkDangerousPath는 시스템 중요 경로의 파일 삭제를 차단한다.
func checkDangerousPath(cleaned string) error {
	normalized := strings.ToLower(filepath.ToSlash(cleaned))

	var blocked []string
	if runtime.GOOS == "windows" {
		winDir := os.Getenv("WINDIR")
		if winDir == "" {
			winDir = `C:\Windows`
		}
		blocked = []string{
			strings.ToLower(filepath.ToSlash(winDir)) + "/",
		}
	} else {
		blocked = []string{
			"/etc/", "/boot/", "/sbin/", "/usr/sbin/",
			"/proc/", "/sys/", "/dev/",
			"/var/run/", "/run/",           // 런타임 소켓/PID
			"/usr/lib/systemd/",            // systemd 유닛
			"/lib/systemd/",                // CentOS/RHEL systemd
			"/usr/lib64/",                  // RHEL/CentOS 라이브러리
			"/lib64/",                      // RHEL/CentOS 라이브러리
			"/lib/", "/usr/lib/",           // 시스템 라이브러리
			"/root/",                       // root 홈
		}
	}

	for _, prefix := range blocked {
		if strings.HasPrefix(normalized, prefix) {
			return fmt.Errorf("deletion of system files is not allowed: %s", cleaned)
		}
	}
	return nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete",
		Description: "Deletes a single file. Safety: no directory/symlink deletion, no path traversal, no system files, TOCTOU protection. Use dry_run=true to preview.",
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, DeleteOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, DeleteOutput{Result: msg}, nil
}
