package sftp

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// maxTransferSize is the maximum file size for upload/download (2 GB).
	maxTransferSize int64 = 2 * 1024 * 1024 * 1024

	// maxListEntries is the maximum number of entries returned by ls.
	maxListEntries = 500

	// maxDeleteItems is the maximum number of items deleted in recursive rm.
	maxDeleteItems = 10000
)

// dangerousRemotePaths lists remote paths that should never be recursively deleted.
var dangerousRemotePaths = map[string]bool{
	"/":      true,
	"/home":  true,
	"/root":  true,
	"/etc":   true,
	"/var":   true,
	"/usr":   true,
	"/bin":   true,
	"/sbin":  true,
	"/boot":  true,
	"/dev":   true,
	"/proc":  true,
	"/sys":   true,
	"/tmp":   true,
	"/opt":   true,
	"/lib":   true,
	"/lib64": true,
}

// validateRemotePath checks that a remote path is safe to use.
func validateRemotePath(path string) error {
	if path == "" {
		return fmt.Errorf("remote_path is required")
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("remote_path contains null byte")
	}
	return nil
}

// sensitiveLocalDirs lists directory basenames that should be protected from SFTP writes.
var sensitiveLocalDirs = map[string]bool{
	".ssh":    true,
	".gnupg":  true,
	".config": true,
	".kube":   true,
	".docker": true,
	".aws":    true,
	".azure":  true,
	".gcloud": true,
	".npmrc":  true,
	".pypirc": true,
	".gem":    true,
	".cargo":  true,
}

// sensitiveLocalFiles lists filenames that should be protected from SFTP writes.
var sensitiveLocalFiles = map[string]bool{
	".bashrc":         true,
	".bash_profile":   true,
	".zshrc":          true,
	".profile":        true,
	".gitconfig":      true,
	".netrc":          true,
	".env":            true,
	"id_rsa":          true,
	"id_ed25519":      true,
	"authorized_keys": true,
	"known_hosts":     true,
}

// validateLocalPath checks that a local path is safe for file transfer.
func validateLocalPath(path string) error {
	if path == "" {
		return fmt.Errorf("local_path is required")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("local_path must be an absolute path")
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("local_path contains null byte")
	}
	return nil
}

// isSensitiveLocalPath checks if a local path targets a sensitive location.
// Used for download/write operations to prevent overwriting critical files.
func isSensitiveLocalPath(path string) error {
	cleaned := filepath.Clean(path)

	// Resolve the final link and existing ancestors even when a new child does
	// not exist yet. Looking up only the parent misses both of those cases.
	resolved, err := resolveDownloadDestination(cleaned, 0)
	if err != nil {
		return fmt.Errorf("cannot verify download destination: %w", err)
	}
	cleaned = resolved

	// Check each component of the path for sensitive directories
	parts := strings.Split(filepath.ToSlash(cleaned), "/")
	for _, part := range parts {
		if runtime.GOOS == "windows" {
			part = strings.ToLower(strings.TrimRight(part, ". "))
		}
		if sensitiveLocalDirs[part] {
			return fmt.Errorf("refusing to write to sensitive directory %q in path: %s", part, path)
		}
	}

	// Check filename
	baseName := filepath.Base(cleaned)
	if runtime.GOOS == "windows" {
		baseName = strings.ToLower(strings.TrimRight(baseName, ". "))
	}
	if sensitiveLocalFiles[baseName] {
		return fmt.Errorf("refusing to write to sensitive file: %s", baseName)
	}

	return nil
}

func resolveDownloadDestination(p string, depth int) (string, error) {
	if depth > 256 {
		return "", fmt.Errorf("download path resolution limit exceeded")
	}
	info, err := os.Lstat(p)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				return "", err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(p), target)
			}
			return resolveDownloadDestination(target, depth+1)
		}
		return filepath.EvalSymlinks(p)
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(p)
	if parent == p {
		return "", err
	}
	resolved, err := resolveDownloadDestination(parent, depth+1)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(p)), nil
}

// isDangerousPath checks if a remote path is too dangerous for recursive delete.
func isDangerousPath(remotePath string) bool {
	// A configured Windows drive root must be as protected as POSIX /.
	windowsPath := strings.ReplaceAll(remotePath, "\\", "/")
	if len(windowsPath) >= 3 && windowsPath[1] == ':' && strings.HasPrefix(windowsPath[2:], "/") && posixClean(windowsPath[2:]) == "/" {
		return true
	}
	cleaned := posixClean(remotePath)
	return dangerousRemotePaths[cleaned]
}

// posixClean normalizes a POSIX path (remote paths are always POSIX).
func posixClean(p string) string {
	// Trim trailing slashes, then normalize
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "/"
	}
	// Collapse double slashes and resolve . / ..
	parts := strings.Split(p, "/")
	var cleaned []string
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(cleaned) > 0 {
				cleaned = cleaned[:len(cleaned)-1]
			}
		default:
			cleaned = append(cleaned, part)
		}
	}
	return "/" + strings.Join(cleaned, "/")
}

// formatSize formats a byte count as a human-readable string.
func formatSize(bytes int64) string {
	if bytes >= 1024*1024*1024 {
		return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
	}
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	if bytes >= 1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%d B", bytes)
}
