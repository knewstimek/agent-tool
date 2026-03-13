package backup

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type BackupInput struct {
	Source    string   `json:"source" jsonschema:"description=Absolute path to the directory to backup"`
	OutputDir string   `json:"output_dir" jsonschema:"description=Absolute path to the backup output directory. Default: ./backups/"`
	Excludes []string `json:"excludes" jsonschema:"description=Glob patterns to exclude (e.g. node_modules, *.log, .git)"`
}

type BackupOutput struct {
	Result    string `json:"result"`
	ArchivePath string `json:"archive_path"`
	FileCount int    `json:"file_count"`
}

// 기본 제외 패턴
var defaultExcludes = []string{
	".git",
	"node_modules",
	"__pycache__",
	".cache",
	"*.exe",
	"*.dll",
	"*.so",
	"*.dylib",
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input BackupInput) (*mcp.CallToolResult, BackupOutput, error) {
	if input.Source == "" {
		return errorResult("source is required")
	}
	if !filepath.IsAbs(input.Source) {
		return errorResult("source must be an absolute path")
	}

	fi, err := os.Stat(input.Source)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("source not found: %s", input.Source))
		}
		return errorResult(fmt.Sprintf("cannot access source: %v", err))
	}
	if !fi.IsDir() {
		return errorResult("source must be a directory")
	}

	// 출력 디렉토리
	outputDir := input.OutputDir
	if outputDir == "" {
		outputDir = filepath.Join(input.Source, "backups")
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return errorResult(fmt.Sprintf("failed to create output directory: %v", err))
	}

	// 타임스탬프 파일명 생성
	dirName := filepath.Base(input.Source)
	timestamp := time.Now().Format("20060102_150405")
	archivePath := filepath.Join(outputDir, fmt.Sprintf("%s_%s.zip", dirName, timestamp))

	// 제외 패턴 (기본 + 사용자 지정)
	excludes := append([]string{}, defaultExcludes...)
	excludes = append(excludes, input.Excludes...)

	// 백업 디렉토리 자체도 제외
	absOutputDir, _ := filepath.Abs(outputDir)

	count, err := createBackupZip(archivePath, input.Source, excludes, absOutputDir)
	if err != nil {
		return errorResult(fmt.Sprintf("backup failed: %v", err))
	}

	msg := fmt.Sprintf("OK: backed up %d files → %s", count, archivePath)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, BackupOutput{Result: msg, ArchivePath: archivePath, FileCount: count}, nil
}

func createBackupZip(output, sourceDir string, excludes []string, backupDir string) (int, error) {
	f, err := os.Create(output)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	w := zip.NewWriter(f)
	defer w.Close()

	count := 0
	err = filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// 백업 출력 디렉토리 자체를 스킵
		absPath, _ := filepath.Abs(path)
		if strings.HasPrefix(absPath, backupDir) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// 제외 패턴 체크
		if shouldExclude(info.Name(), info.IsDir(), excludes) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if info.IsDir() {
			return nil
		}

		rel, _ := filepath.Rel(sourceDir, path)
		archivePath := filepath.ToSlash(rel)

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return nil
		}
		header.Name = archivePath
		header.Method = zip.Deflate

		writer, err := w.CreateHeader(header)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return nil // 읽기 실패한 파일은 스킵
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		if err != nil {
			return nil
		}

		count++
		return nil
	})

	return count, err
}

func shouldExclude(name string, isDir bool, excludes []string) bool {
	for _, pattern := range excludes {
		// 디렉토리 이름 매칭 (예: node_modules, .git)
		if isDir && name == pattern {
			return true
		}
		// glob 패턴 매칭 (예: *.log, *.exe)
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "backup",
		Description: `Creates a timestamped zip backup of a directory.
Output: {dirname}_{YYYYMMDD_HHMMSS}.zip
Default excludes: .git, node_modules, __pycache__, binaries.
Custom excludes can be added via the excludes parameter.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, BackupOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, BackupOutput{}, nil
}
