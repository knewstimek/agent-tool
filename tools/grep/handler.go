package grep

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/edit"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var errMaxResults = errors.New("max results reached")

type GrepInput struct {
	Pattern    string `json:"pattern" jsonschema:"description=Regular expression pattern to search for"`
	Path       string `json:"path" jsonschema:"description=File or directory to search in (absolute path)"`
	Glob       string `json:"glob" jsonschema:"description=Glob pattern to filter files (e.g. *.go). Only used when path is a directory"`
	IgnoreCase bool   `json:"ignore_case" jsonschema:"description=Case insensitive search (default false)"`
	MaxResults int    `json:"max_results" jsonschema:"description=Maximum number of matching lines to return. Default: 100"`
}

type GrepOutput struct {
	Matches []string `json:"matches"`
	Count   int      `json:"count"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input GrepInput) (*mcp.CallToolResult, GrepOutput, error) {
	if input.Pattern == "" {
		return errorResult("pattern is required")
	}
	if input.Path == "" {
		return errorResult("path is required")
	}
	if !filepath.IsAbs(input.Path) {
		return errorResult("path must be an absolute path")
	}

	flags := ""
	if input.IgnoreCase {
		flags = "(?i)"
	}
	re, err := regexp.Compile(flags + input.Pattern)
	if err != nil {
		return errorResult(fmt.Sprintf("invalid regex pattern: %v", err))
	}

	maxResults := input.MaxResults
	if maxResults <= 0 {
		maxResults = 100
	}

	fi, err := os.Stat(input.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("path not found: %s", input.Path))
		}
		return errorResult(fmt.Sprintf("cannot access path: %v", err))
	}

	var matches []string

	if fi.IsDir() {
		matches, err = searchDir(input.Path, input.Glob, re, maxResults)
	} else {
		matches, err = searchFile(input.Path, re, maxResults)
	}

	if err != nil {
		return errorResult(fmt.Sprintf("search error: %v", err))
	}

	var sb strings.Builder
	for _, m := range matches {
		sb.WriteString(m)
		sb.WriteString("\n")
	}

	text := sb.String()
	if len(matches) == 0 {
		text = "No matches found"
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, GrepOutput{Matches: matches, Count: len(matches)}, nil
}

func searchFile(path string, re *regexp.Regexp, maxResults int) ([]string, error) {
	hintCharset := edit.FindEditorConfigCharset(path)
	content, _, err := common.ReadFileWithEncoding(path, hintCharset)
	if err != nil {
		return nil, err
	}

	var matches []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if re.MatchString(line) {
			matches = append(matches, fmt.Sprintf("%s:%d:%s", path, lineNum, line))
			if len(matches) >= maxResults {
				break
			}
		}
	}
	return matches, nil
}

func searchDir(dir, globPattern string, re *regexp.Regexp, maxResults int) ([]string, error) {
	var matches []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // 접근 불가 파일은 스킵
		}
		if info.IsDir() {
			// .git 등 숨김 디렉토리 스킵
			if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}

		// glob 필터
		if globPattern != "" {
			matched, _ := filepath.Match(globPattern, info.Name())
			if !matched {
				return nil
			}
		}

		// 바이너리 파일 스킵 (간단한 휴리스틱)
		if isBinaryExt(info.Name()) {
			return nil
		}

		fileMatches, err := searchFile(path, re, maxResults-len(matches))
		if err != nil {
			return nil // 읽기 실패한 파일은 스킵
		}
		matches = append(matches, fileMatches...)

		if len(matches) >= maxResults {
			return errMaxResults
		}
		return nil
	})

	if err != nil && !errors.Is(err, errMaxResults) {
		return matches, err
	}
	return matches, nil
}

func isBinaryExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".obj": true, ".o": true, ".a": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".bmp": true, ".ico": true, ".svg": true,
		".zip": true, ".tar": true, ".gz": true, ".7z": true, ".rar": true,
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
		".pyc": true, ".class": true,
	}
	return binaryExts[ext]
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "grep",
		Description: `Searches file contents for a regex pattern.
Encoding-aware: auto-detects file encoding.
Can search a single file or recursively search a directory.
Supports glob filtering and case-insensitive search.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, GrepOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, GrepOutput{}, nil
}
