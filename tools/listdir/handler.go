package listdir

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ListDirInput struct {
	Path          string `json:"path" jsonschema:"Absolute path to the directory to list"`
	MaxDepth      int    `json:"max_depth,omitempty" jsonschema:"Maximum depth for tree traversal. Default: 3"`
	RelativePaths bool   `json:"relative_paths,omitempty" jsonschema:"Show the root as '.' instead of the full absolute path. Saves tokens in output. Default: false"`
}

type ListDirOutput struct {
	Tree       string `json:"tree"`
	TotalFiles int    `json:"total_files"`
	TotalDirs  int    `json:"total_dirs"`
}

// 스킵할 디렉토리
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"__pycache__":  true,
	".next":        true,
	".nuxt":        true,
	"dist":         true,
	"build":        true,
	".cache":       true,
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ListDirInput) (*mcp.CallToolResult, ListDirOutput, error) {
	if input.Path == "" {
		return errorResult("path is required")
	}
	if !filepath.IsAbs(input.Path) {
		return errorResult("path must be an absolute path")
	}

	fi, err := os.Stat(input.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("directory not found: %s", input.Path))
		}
		return errorResult(fmt.Sprintf("cannot access path: %v", err))
	}
	if !fi.IsDir() {
		return errorResult(fmt.Sprintf("path is not a directory: %s", input.Path))
	}

	maxDepth := input.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}

	var sb strings.Builder
	totalFiles := 0
	totalDirs := 0

	if input.RelativePaths {
		sb.WriteString(".\n")
	} else {
		sb.WriteString(input.Path)
		sb.WriteString("\n")
	}

	buildTree(&sb, input.Path, "", 0, maxDepth, &totalFiles, &totalDirs)

	summary := fmt.Sprintf("\n(%d directories, %d files)", totalDirs, totalFiles)
	sb.WriteString(summary)

	text := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, ListDirOutput{Tree: text, TotalFiles: totalFiles, TotalDirs: totalDirs}, nil
}

func buildTree(sb *strings.Builder, dir, prefix string, depth, maxDepth int, totalFiles, totalDirs *int) {
	if depth >= maxDepth {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	// 숨김 파일/디렉토리 필터링 (. 으로 시작)
	var visible []os.DirEntry
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			visible = append(visible, e)
		}
	}

	for i, entry := range visible {
		isLast := i == len(visible)-1

		connector := "├── "
		childPrefix := "│   "
		if isLast {
			connector = "└── "
			childPrefix = "    "
		}

		sb.WriteString(prefix)
		sb.WriteString(connector)
		sb.WriteString(entry.Name())

		if entry.IsDir() {
			sb.WriteString("/\n")
			*totalDirs++

			if skipDirs[entry.Name()] {
				sb.WriteString(prefix)
				sb.WriteString(childPrefix)
				sb.WriteString("└── ...\n")
				continue
			}

			buildTree(sb, filepath.Join(dir, entry.Name()), prefix+childPrefix, depth+1, maxDepth, totalFiles, totalDirs)
		} else {
			sb.WriteString("\n")
			*totalFiles++
		}
	}
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "listdir",
		Description: `Lists directory contents in a tree structure.
Shows files and directories with visual tree connectors (├── └──).
Skips hidden directories and common build/vendor directories.
Use max_depth to control traversal depth (default: 3).
Use relative_paths=true to show root as '.' instead of full path (saves tokens).`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, ListDirOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ListDirOutput{}, nil
}
