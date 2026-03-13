package glob

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

	// 수정 시간 기준 정렬 (최신 먼저)
	sort.Slice(matches, func(i, j int) bool {
		fi, _ := os.Stat(matches[i])
		fj, _ := os.Stat(matches[j])
		if fi == nil || fj == nil {
			return false
		}
		return fi.ModTime().After(fj.ModTime())
	})

	// 최대 500개로 제한
	if len(matches) > 500 {
		matches = matches[:500]
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

func findMatches(baseDir, pattern string) ([]string, error) {
	var matches []string

	// ** 패턴 지원: 재귀 탐색
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
