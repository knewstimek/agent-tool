package copy

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type CopyInput struct {
	Source      string `json:"source" jsonschema:"Absolute path to the source file or directory,required"`
	Destination string `json:"destination" jsonschema:"Absolute path to the destination,required"`
	Overwrite   bool   `json:"overwrite,omitempty" jsonschema:"Overwrite existing destination. Default: false"`
	DryRun      bool   `json:"dry_run,omitempty" jsonschema:"Preview what would be copied without doing it (default false)"`
}

type CopyOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input CopyInput) (*mcp.CallToolResult, CopyOutput, error) {
	if input.Source == "" || input.Destination == "" {
		return errorResult("both source and destination are required")
	}
	if !filepath.IsAbs(input.Source) || !filepath.IsAbs(input.Destination) {
		return errorResult("both paths must be absolute")
	}

	srcCleaned := filepath.Clean(input.Source)
	dstCleaned := filepath.Clean(input.Destination)

	// Block ".." traversal
	for _, p := range []string{srcCleaned, dstCleaned} {
		for _, part := range strings.Split(filepath.ToSlash(p), "/") {
			if part == ".." {
				return errorResult("path traversal (..) is not allowed")
			}
		}
	}

	if srcCleaned == dstCleaned {
		return errorResult("source and destination are the same")
	}

	// Check source exists
	srcInfo, err := os.Lstat(srcCleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("source not found: %s", srcCleaned))
		}
		return errorResult(fmt.Sprintf("cannot access source: %v", err))
	}

	// Reject symlinks when not allowed
	if srcInfo.Mode()&os.ModeSymlink != 0 {
		if !common.GetAllowSymlinks() {
			return errorResult("source is a symlink and allow_symlinks is disabled")
		}
		// Resolve symlink to get actual type (Lstat returns symlink info, not target)
		srcInfo, err = os.Stat(srcCleaned)
		if err != nil {
			return errorResult(fmt.Sprintf("cannot resolve symlink: %v", err))
		}
	}

	// Check destination
	if !input.Overwrite {
		if _, err := os.Stat(dstCleaned); err == nil {
			return errorResult(fmt.Sprintf("destination already exists: %s (use overwrite=true to replace)", dstCleaned))
		}
	}

	if srcInfo.IsDir() {
		return handleDirCopy(srcCleaned, dstCleaned, input.DryRun, input.Overwrite)
	}
	return handleFileCopy(srcCleaned, dstCleaned, srcInfo, input.DryRun)
}

// handleDirCopy copies a directory recursively.
func handleDirCopy(src, dst string, dryRun, overwrite bool) (*mcp.CallToolResult, CopyOutput, error) {
	// Prevent copying a directory into itself (either direction).
	// Windows NTFS is case-insensitive, so normalize case before comparison
	// to prevent bypassing via "C:\Foo" vs "C:\foo".
	dstSlash := filepath.ToSlash(dst) + "/"
	srcSlash := filepath.ToSlash(src) + "/"
	if runtime.GOOS == "windows" {
		dstSlash = strings.ToLower(dstSlash)
		srcSlash = strings.ToLower(srcSlash)
	}
	if strings.HasPrefix(dstSlash, srcSlash) {
		return errorResult("cannot copy a directory into itself")
	}
	if strings.HasPrefix(srcSlash, dstSlash) {
		return errorResult("source is inside destination directory")
	}

	const maxCopyFiles = 10000
	var fileCount int
	var totalSize int64

	// WalkDir uses Lstat internally, so d.Type() correctly detects symlinks
	// (unlike filepath.Walk which follows symlinks and hides them).
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip symlinks when not allowed.
		// WalkDir uses Lstat, so symlink entries never have IsDir()=true — just skip.
		if d.Type()&os.ModeSymlink != 0 && !common.GetAllowSymlinks() {
			return nil
		}

		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			fileCount++
			if fileCount > maxCopyFiles {
				return fmt.Errorf("too many files (>%d), aborting", maxCopyFiles)
			}
			totalSize += info.Size()
		}
		return nil
	})
	if err != nil {
		return errorResult(fmt.Sprintf("failed to scan source directory: %v", err))
	}

	if dryRun {
		msg := fmt.Sprintf("[DRY RUN] would copy directory: %s → %s\nFiles: %d, Total size: %s",
			src, dst, fileCount, formatSize(totalSize))
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, CopyOutput{Result: msg}, nil
	}

	// Perform actual copy
	copiedFiles := 0
	err = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip symlinks when not allowed.
		// WalkDir uses Lstat, so symlink entries never have IsDir()=true — just skip.
		if d.Type()&os.ModeSymlink != 0 && !common.GetAllowSymlinks() {
			return nil
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)

		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(dstPath, info.Mode())
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		if err := copyFileAtomic(path, dstPath, info.Mode()); err != nil {
			return fmt.Errorf("copy %s: %w", relPath, err)
		}
		copiedFiles++
		return nil
	})
	if err != nil {
		return errorResult(fmt.Sprintf("copy failed: %v", err))
	}

	msg := fmt.Sprintf("OK: copied directory %s → %s (%d files, %s)",
		src, dst, copiedFiles, formatSize(totalSize))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, CopyOutput{Result: msg}, nil
}

// handleFileCopy copies a single file.
func handleFileCopy(src, dst string, srcInfo os.FileInfo, dryRun bool) (*mcp.CallToolResult, CopyOutput, error) {
	if dryRun {
		msg := fmt.Sprintf("[DRY RUN] would copy file: %s → %s\nSize: %s",
			src, dst, formatSize(srcInfo.Size()))
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, CopyOutput{Result: msg}, nil
	}

	// Create parent directories
	dstDir := filepath.Dir(dst)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return errorResult(fmt.Sprintf("create directory: %v", err))
	}

	if err := copyFileAtomic(src, dst, srcInfo.Mode()); err != nil {
		return errorResult(fmt.Sprintf("copy failed: %v", err))
	}

	msg := fmt.Sprintf("OK: copied file %s → %s (%s)", src, dst, formatSize(srcInfo.Size()))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, CopyOutput{Result: msg}, nil
}

// copyFileAtomic copies a file using temp file + rename for atomicity.
func copyFileAtomic(src, dst string, mode os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstDir := filepath.Dir(dst)
	tmpFile, err := os.CreateTemp(dstDir, ".agent-tool-copy-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	renamed := false
	closed := false
	defer func() {
		if !closed {
			tmpFile.Close()
		}
		if !renamed {
			os.Remove(tmpPath)
		}
	}()

	if _, err := io.Copy(tmpFile, srcFile); err != nil {
		return err
	}
	// Explicit close before chmod/rename — check error to catch deferred write failures
	if err := tmpFile.Close(); err != nil {
		return err
	}
	closed = true

	// Preserve source permissions
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	renamed = true
	return nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "copy",
		Description: `Copies a file or directory to a new location.
File copy uses atomic write (temp file + rename) and preserves permissions.
Directory copy recreates the full directory structure recursively.
Use dry_run=true to preview what would be copied without doing it.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, CopyOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, CopyOutput{Result: msg}, nil
}

func formatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}
