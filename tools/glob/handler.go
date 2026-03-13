package glob

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GlobInput struct {
	Pattern string `json:"pattern" jsonschema:"description=Glob pattern to match files (e.g. **/*.go or src/**/*.ts)"`
	Path    string `json:"path" jsonschema:"description=Directory to search in (absolute path). Defaults to current directory if empty"`
}

type GlobOutput struct {
	Files []string `json:"files"`
	Count int      `json:"count"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input GlobInput) (*mcp.CallToolResult, GlobOutput, error) {
	if input.Pattern == "" {
		return errorResult("pattern is required")
	}

	searchDir := input.Path
	if searchDir == "" {
		var err error
		searchDir, err = os.Getwd()
		if err != nil {
			return errorResult(fmt.Sprintf("failed to get working directory: %v", err))
		}
	}

	if !filepath.IsAbs(searchDir) {
		return errorResult("path must be an absolute path")
	}

	if _, err := os.Stat(searchDir); os.IsNotExist(err) {
		return errorResult(fmt.Sprintf("directory not found: %s", searchDir))
	}

	matches, err := findMatches(searchDir, input.Pattern)
	if err != nil {
		return errorResult(fmt.Sprintf("glob error: %v", err))
	}

	// 수정 시간 기준 정렬 (최신 먼저).
	// sort.Slice 내에서 매 비교마다 os.Stat를 호출하면 O(N log N) syscall이 발생하므로,
	// 미리 한 번 순회하며 modTime을 캐싱하여 O(N) syscall로 제한한다.
	type fileWithTime struct {
		path    string
		modTime time.Time
		valid   bool
	}
	filesWithTime := make([]fileWithTime, len(matches))
	for i, m := range matches {
		fi, err := os.Stat(m)
		if err != nil {
			filesWithTime[i] = fileWithTime{path: m}
		} else {
			filesWithTime[i] = fileWithTime{path: m, modTime: fi.ModTime(), valid: true}
		}
	}
	sort.Slice(filesWithTime, func(i, j int) bool {
		if !filesWithTime[i].valid {
			return false // stat 실패 파일은 뒤로
		}
		if !filesWithTime[j].valid {
			return true
		}
		return filesWithTime[i].modTime.After(filesWithTime[j].modTime)
	})

	// stat 실패 파일(삭제됨, 권한 없음 등)은 결과에서 제외한다.
	// 500개 제한은 유효한 파일만 카운트하여 사용자가 요청한 만큼 결과를 받을 수 있게 한다.
	matches = matches[:0]
	for _, ft := range filesWithTime {
		if !ft.valid {
			continue
		}
		matches = append(matches, ft.path)
		if len(matches) >= 500 {
			break
		}
	}

	var sb strings.Builder
	for _, m := range matches {
		sb.WriteString(m)
		sb.WriteString("\n")
	}

	text := sb.String()
	if len(matches) == 0 {
		text = "No files matched the pattern"
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, GlobOutput{Files: matches, Count: len(matches)}, nil
}

// findMatches는 baseDir에서 pattern에 매칭되는 파일 경로를 반환한다.
// "**" 패턴은 재귀 디렉토리 탐색으로 처리하며, 숨김 디렉토리(.git 등)와
// node_modules, vendor는 자동 스킵한다.
// 예: "**/*.go" → baseDir 하위 모든 .go 파일
//     "src/**/*.ts" → baseDir/src/ 하위 모든 .ts 파일
func findMatches(baseDir, pattern string) ([]string, error) {
	var matches []string

	// ** 패턴 지원: 재귀 탐색
	// 단순 구현: **는 한 번만 처리하며, ** 뒤 suffix는 파일명 glob으로 매칭한다.
	// 예: "src/**/*.ts" → prefix="src/", suffix="*.ts"
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		prefix := parts[0]
		suffix := ""
		if len(parts) > 1 {
			suffix = strings.TrimPrefix(parts[1], "/")
			suffix = strings.TrimPrefix(suffix, "\\")
		}

		startDir := filepath.Join(baseDir, filepath.FromSlash(prefix))
		if _, err := os.Stat(startDir); os.IsNotExist(err) {
			startDir = baseDir
		}

		err := filepath.Walk(startDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
					return filepath.SkipDir
				}
				if info.Name() == "node_modules" || info.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}

			if suffix == "" {
				matches = append(matches, path)
				return nil
			}

			matched, _ := filepath.Match(suffix, info.Name())
			if matched {
				matches = append(matches, path)
			}
			return nil
		})
		return matches, err
	}

	// 일반 glob 패턴
	fullPattern := filepath.Join(baseDir, filepath.FromSlash(pattern))
	return filepath.Glob(fullPattern)
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "glob",
		Description: `Finds files matching a glob pattern.
Supports ** for recursive directory matching.
Returns matching file paths sorted by modification time (newest first).
Skips hidden directories (.git, etc.) and common vendor directories.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, GlobOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, GlobOutput{}, nil
}
