package delete

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"agent-tool/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type DeleteInput struct {
	FilePath  string      `json:"file_path,omitempty" jsonschema:"File or directory to delete. Relative paths use workspace/MCP root"`
	FilePaths []string    `json:"file_paths,omitempty" jsonschema:"Files or directories to delete in one batch. Maximum 100. Cannot be combined with file_path or path"`
	Path      string      `json:"path,omitempty" jsonschema:"Alias for file_path"`
	Recursive interface{} `json:"recursive,omitempty" jsonschema:"Delete a directory and all of its contents: true or false. Required for directory deletion. Default: false"`
	DryRun    interface{} `json:"dry_run,omitempty" jsonschema:"Preview deletion without actually removing the file: true or false. Default: false"`
}

type DeleteOutput struct {
	Result string `json:"result"`
	files  int
	dirs   int
	bytes  int64
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input DeleteInput) (*mcp.CallToolResult, DeleteOutput, error) {
	if len(input.FilePaths) > 0 {
		return handleBatch(ctx, req, input)
	}
	return handleSingle(ctx, req, input)
}

func handleSingle(ctx context.Context, req *mcp.CallToolRequest, input DeleteInput) (*mcp.CallToolResult, DeleteOutput, error) {
	if input.FilePath == "" {
		input.FilePath = input.Path
	}
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	resolvedPath, err := common.ResolveRequestPath(ctx, req, input.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot resolve file_path: %v", err))
	}
	input.FilePath = resolvedPath

	// Normalize path
	cleaned := filepath.Clean(input.FilePath)

	// [FIX #4] Check for ".." per path component (avoid false positives from consecutive dots in filenames)
	for _, part := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if part == ".." {
			return errorResult("path traversal (..) is not allowed")
		}
	}

	// [FIX #2] Block Windows reserved device names
	if runtime.GOOS == "windows" {
		if err := checkWindowsReserved(cleaned); err != nil {
			return errorResult(err.Error())
		}
	}

	// [FIX #3] Block critical system paths
	if err := checkDangerousPath(cleaned); err != nil {
		return errorResult(err.Error())
	}

	// Check file info
	info, err := os.Lstat(cleaned) // Lstat: does not follow symlinks
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", cleaned))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}

	// Directory deletion requires explicit recursive opt-in.
	if info.IsDir() {
		if !common.FlexBool(input.Recursive) {
			return errorResult("path is a directory; directory deletion requires recursive=true. Use dry_run=true with recursive=true to preview the affected files and directories")
		}
		return deleteDirectory(ctx, req, cleaned, common.FlexBool(input.DryRun))
	}

	// Symlink deletion is not allowed
	if info.Mode()&os.ModeSymlink != 0 {
		return errorResult("symlink deletion is not allowed for safety")
	}

	// dry_run mode
	if common.FlexBool(input.DryRun) {
		msg := fmt.Sprintf("[DRY RUN] would delete: %s (%d bytes)", cleaned, info.Size())
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, DeleteOutput{Result: msg, files: 1, bytes: info.Size()}, nil
	}

	// [FIX #1] TOCTOU mitigation: re-check file state right before deletion
	info2, err := os.Lstat(cleaned)
	if err != nil {
		return errorResult(fmt.Sprintf("pre-delete check failed: %v", err))
	}
	if info2.IsDir() || info2.Mode()&os.ModeSymlink != 0 {
		return errorResult("file type changed before deletion (possible race condition)")
	}

	// Perform actual deletion
	if err := os.Remove(cleaned); err != nil {
		return errorResult(fmt.Sprintf("delete failed: %v", err))
	}

	msg := fmt.Sprintf("OK: deleted %s (%d bytes)", cleaned, info.Size())
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, DeleteOutput{Result: msg, files: 1, bytes: info.Size()}, nil
}

const (
	maxBatchPaths  = 100
	maxBatchErrors = 10
)

func handleBatch(ctx context.Context, req *mcp.CallToolRequest, input DeleteInput) (*mcp.CallToolResult, DeleteOutput, error) {
	if input.FilePath != "" || input.Path != "" {
		return errorResult("file_paths cannot be combined with file_path or path; use either one single-path field or file_paths")
	}
	if len(input.FilePaths) > maxBatchPaths {
		return errorResult(fmt.Sprintf("file_paths contains %d paths; maximum is %d. Split the request into smaller batches", len(input.FilePaths), maxBatchPaths))
	}

	resolved := make([]string, len(input.FilePaths))
	seen := make(map[string]int, len(input.FilePaths))
	for i, path := range input.FilePaths {
		if strings.TrimSpace(path) == "" {
			return errorResult(fmt.Sprintf("file_paths[%d] is empty; provide a file or directory path", i))
		}
		cleaned, err := common.ResolveRequestPath(ctx, req, path)
		if err != nil {
			return errorResult(fmt.Sprintf("cannot resolve file_paths[%d] %q: %v", i, path, err))
		}
		key := filepath.Clean(cleaned)
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if previous, ok := seen[key]; ok {
			return errorResult(fmt.Sprintf("file_paths[%d] duplicates file_paths[%d]: %s; remove the duplicate and retry", i, previous, cleaned))
		}
		seen[key] = i
		resolved[i] = cleaned
	}

	for i := 0; i < len(resolved); i++ {
		for j := i + 1; j < len(resolved); j++ {
			if pathIsSameOrAncestor(resolved[i], resolved[j]) || pathIsSameOrAncestor(resolved[j], resolved[i]) {
				return errorResult(fmt.Sprintf("file_paths[%d] and file_paths[%d] overlap (%s and %s); remove the parent or child target to avoid deleting the same tree twice", i, j, resolved[i], resolved[j]))
			}
		}
	}

	var succeeded, files, dirs int
	var bytes int64
	failures := make([]string, 0)
	for i, path := range resolved {
		result, out, err := handleSingle(ctx, req, DeleteInput{
			FilePath:  path,
			Recursive: input.Recursive,
			DryRun:    input.DryRun,
		})
		if err != nil || result.IsError {
			if len(failures) < maxBatchErrors {
				reason := out.Result
				if err != nil {
					reason = err.Error()
				}
				failures = append(failures, fmt.Sprintf("- file_paths[%d] %s: %s", i, input.FilePaths[i], reason))
			}
			continue
		}
		succeeded++
		files += out.files
		dirs += out.dirs
		bytes += out.bytes
	}

	failed := len(input.FilePaths) - succeeded
	dryRun := common.FlexBool(input.DryRun)
	var summary string
	if dryRun {
		summary = fmt.Sprintf("[DRY RUN] %d/%d targets passed validation (%d files, %d directories, %s); %d errors", succeeded, len(input.FilePaths), files, dirs, formatBatchBytes(bytes), failed)
	} else if failed == 0 {
		summary = fmt.Sprintf("OK: deleted %d/%d targets (%d files, %d directories, %s); 0 errors", succeeded, len(input.FilePaths), files, dirs, formatBatchBytes(bytes))
	} else {
		summary = fmt.Sprintf("PARTIAL: deleted %d/%d targets (%d files, %d directories, %s); %d errors", succeeded, len(input.FilePaths), files, dirs, formatBatchBytes(bytes), failed)
	}
	if len(failures) > 0 {
		summary += "\n" + strings.Join(failures, "\n")
	}
	if failed > len(failures) {
		summary += fmt.Sprintf("\n... %d additional errors omitted; retry them in a smaller batch for details", failed-len(failures))
	}

	output := DeleteOutput{Result: summary, files: files, dirs: dirs, bytes: bytes}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		IsError: failed > 0,
	}, output, nil
}

func formatBatchBytes(bytes int64) string {
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	if bytes >= 1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%d bytes", bytes)
}

// checkWindowsReserved blocks Windows reserved device names and ADS paths.
func checkWindowsReserved(cleaned string) error {
	// Block ADS (Alternate Data Stream): another colon after the drive letter colon indicates ADS
	drive := filepath.VolumeName(cleaned)
	rest := cleaned[len(drive):]
	if strings.Contains(rest, ":") {
		return fmt.Errorf("alternate data stream (ADS) paths are not allowed")
	}

	// Block reserved device names
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

// checkDangerousPath blocks file deletion in critical system paths.
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
			"/var/run/", "/run/", // runtime sockets/PIDs
			"/usr/lib/systemd/",  // systemd units
			"/lib/systemd/",      // CentOS/RHEL systemd
			"/usr/lib64/",        // RHEL/CentOS libraries
			"/lib64/",            // RHEL/CentOS libraries
			"/lib/", "/usr/lib/", // system libraries
			"/root/", // root home
		}
	}

	for _, prefix := range blocked {
		if strings.HasPrefix(normalized, prefix) {
			return fmt.Errorf("deletion of system files is not allowed: %s", cleaned)
		}
	}
	return nil
}

const (
	maxDeleteItems = 10000
	maxDeleteDepth = 100
)

type deleteEntry struct {
	path  string
	isDir bool
}

type deletePlan struct {
	entries []deleteEntry
	files   int
	dirs    int
	bytes   int64
}

func deleteDirectory(ctx context.Context, req *mcp.CallToolRequest, cleaned string, dryRun bool) (*mcp.CallToolResult, DeleteOutput, error) {
	if err := checkDangerousDirectory(ctx, req, cleaned); err != nil {
		return errorResult(err.Error())
	}

	plan, err := planDirectoryDelete(cleaned)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot safely delete directory: %v", err))
	}

	if dryRun {
		msg := fmt.Sprintf("[DRY RUN] would recursively delete: %s (%d files, %d directories, %d bytes)", cleaned, plan.files, plan.dirs, plan.bytes)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: msg}}}, DeleteOutput{Result: msg, files: plan.files, dirs: plan.dirs, bytes: plan.bytes}, nil
	}

	// Delete children before parents. Re-check every entry immediately before
	// removal so a path swapped after the safety scan is not followed.
	for i := len(plan.entries) - 1; i >= 0; i-- {
		entry := plan.entries[i]
		info, err := os.Lstat(entry.path)
		if err != nil {
			return errorResult(fmt.Sprintf("recursive delete stopped before %s: path changed after safety scan: %v; some earlier entries may already have been deleted", entry.path, err))
		}
		if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != entry.isDir {
			return errorResult(fmt.Sprintf("recursive delete stopped before %s: file type changed after safety scan; some earlier entries may already have been deleted", entry.path))
		}
		if err := os.Remove(entry.path); err != nil {
			return errorResult(fmt.Sprintf("recursive delete stopped at %s: %v; some earlier entries may already have been deleted", entry.path, err))
		}
	}

	msg := fmt.Sprintf("OK: recursively deleted %s (%d files, %d directories, %d bytes)", cleaned, plan.files, plan.dirs, plan.bytes)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: msg}}}, DeleteOutput{Result: msg, files: plan.files, dirs: plan.dirs, bytes: plan.bytes}, nil
}

func planDirectoryDelete(root string) (deletePlan, error) {
	var plan deletePlan
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link found at %s; recursive deletion does not follow or remove symlinks", path)
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("resolve relative path for %s: %w", path, err)
		}
		depth := 0
		if rel != "." {
			depth = len(strings.Split(filepath.ToSlash(rel), "/"))
		}
		if depth > maxDeleteDepth {
			return fmt.Errorf("directory tree exceeds the maximum depth of %d at %s", maxDeleteDepth, path)
		}
		if len(plan.entries) >= maxDeleteItems {
			return fmt.Errorf("directory tree exceeds the maximum of %d items; narrow the target or remove contents in smaller batches", maxDeleteItems)
		}

		isDir := info.IsDir()
		plan.entries = append(plan.entries, deleteEntry{path: path, isDir: isDir})
		if isDir {
			plan.dirs++
		} else {
			plan.files++
			plan.bytes += info.Size()
		}
		return nil
	})
	return plan, err
}

func checkDangerousDirectory(ctx context.Context, req *mcp.CallToolRequest, target string) error {
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("cannot resolve directory path: %w", err)
	}
	absTarget = filepath.Clean(absTarget)

	volumeRoot := string(filepath.Separator)
	if volume := filepath.VolumeName(absTarget); volume != "" {
		volumeRoot = volume + string(filepath.Separator)
	}
	if samePath(absTarget, volumeRoot) {
		return fmt.Errorf("refusing to recursively delete filesystem root %s; choose a specific child directory", absTarget)
	}

	if workspace, err := filepath.Abs(common.RequestWorkspace(ctx, req)); err == nil && pathIsSameOrAncestor(absTarget, workspace) {
		return fmt.Errorf("refusing to recursively delete the workspace or one of its parents: %s; choose a child directory", absTarget)
	}
	if home, err := os.UserHomeDir(); err == nil && pathIsSameOrAncestor(absTarget, home) {
		return fmt.Errorf("refusing to recursively delete the user home directory or one of its parents: %s; choose a child directory", absTarget)
	}

	for _, protected := range protectedSystemDirectories() {
		if pathsOverlap(absTarget, protected) {
			return fmt.Errorf("refusing to recursively delete protected system path %s (conflicts with %s); choose a non-system directory", absTarget, protected)
		}
	}
	return nil
}

func protectedSystemDirectories() []string {
	if runtime.GOOS == "windows" {
		paths := []string{os.Getenv("WINDIR"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramData")}
		if paths[0] == "" {
			paths[0] = `C:\Windows`
		}
		return paths
	}
	return []string{"/etc", "/boot", "/sbin", "/usr", "/proc", "/sys", "/dev", "/var", "/run", "/lib", "/lib64", "/root"}
}

func pathsOverlap(a, b string) bool {
	if b == "" {
		return false
	}
	return pathIsSameOrAncestor(a, b) || pathIsSameOrAncestor(b, a)
}

func pathIsSameOrAncestor(candidate, path string) bool {
	candidate = filepath.Clean(candidate)
	path = filepath.Clean(path)
	if samePath(candidate, path) {
		return true
	}
	rel, err := filepath.Rel(candidate, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name:        "delete",
		Description: "Deletes one file/directory or up to 100 targets with file_paths. Directory deletion requires recursive=true and is limited to 10,000 items/100 levels per target. Batch results are compactly aggregated. Safety: no symlinks, path traversal, workspace roots, home directories, or system paths. Use dry_run=true to preview.",
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, DeleteOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, DeleteOutput{Result: msg}, nil
}
