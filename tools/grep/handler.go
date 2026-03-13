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

// errMaxResults는 filepath.Walk를 조기 종료하기 위한 센티넬 에러이다.
// 호출자에서 errors.Is로 실제 오류와 구분한다.
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
	hasLowConfidence := false

	if fi.IsDir() {
		var dirResult searchDirResult
		dirResult, err = searchDir(input.Path, input.Glob, re, maxResults)
		matches = dirResult.matches
		hasLowConfidence = dirResult.lowConfidenceCount > 0
	} else {
		var fileResult searchFileResult
		fileResult, err = searchFile(input.Path, re, maxResults)
		matches = fileResult.matches
		hasLowConfidence = fileResult.lowConfidence
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

	// 인코딩 감지 신뢰도 낮은 파일이 있으면 경고 추가
	if hasLowConfidence {
		text += "\n⚠ Some files had low encoding detection confidence. " +
			"Results may be incomplete. Consider setting fallback_encoding via set_config tool " +
			"or adding 'charset' to .editorconfig."
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, GrepOutput{Matches: matches, Count: len(matches)}, nil
}

// searchFileResult는 searchFile의 반환값이다.
type searchFileResult struct {
	matches    []string
	lowConfidence bool // 인코딩 감지 신뢰도가 낮은 파일
}

func searchFile(path string, re *regexp.Regexp, maxResults int) (searchFileResult, error) {
	hintCharset := edit.FindEditorConfigCharset(path)
	content, encInfo, err := common.ReadFileWithEncoding(path, hintCharset)
	if err != nil {
		return searchFileResult{}, err
	}

	result := searchFileResult{
		lowConfidence: common.EncodingWarning(encInfo) != "",
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if re.MatchString(line) {
			result.matches = append(result.matches, fmt.Sprintf("%s:%d:%s", path, lineNum, line))
			if len(result.matches) >= maxResults {
				break
			}
		}
	}
	return result, nil
}

// searchDirResult는 searchDir의 반환값이다.
type searchDirResult struct {
	matches          []string
	lowConfidenceCount int // 인코딩 감지 신뢰도가 낮았던 파일 수
}

func searchDir(dir, globPattern string, re *regexp.Regexp, maxResults int) (searchDirResult, error) {
	result := searchDirResult{}

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

		// 전체 maxResults에서 이미 수집한 수를 빼서 파일별 검색 한도를 제한
		fileResult, err := searchFile(path, re, maxResults-len(result.matches))
		if err != nil {
			return nil // 읽기 실패한 파일은 스킵
		}
		result.matches = append(result.matches, fileResult.matches...)
		if fileResult.lowConfidence {
			result.lowConfidenceCount++
		}

		if len(result.matches) >= maxResults {
			return errMaxResults
		}
		return nil
	})

	if err != nil && !errors.Is(err, errMaxResults) {
		return result, err
	}
	return result, nil
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
