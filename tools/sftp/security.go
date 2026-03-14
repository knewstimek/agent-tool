package sftp

import (
	"fmt"
	"path/filepath"
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
	"/":     true,
	"/home": true,
	"/root": true,
	"/etc":  true,
	"/var":  true,
	"/usr":  true,
	"/bin":  true,
	"/sbin": true,
	"/boot": true,
	"/dev":  true,
	"/proc": true,
	"/sys":  true,
	"/tmp":  true,
	"/opt":  true,
	"/lib":  true,
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
	".ssh":        true,
	".gnupg":      true,
	".config":     true,
	".kube":       true,
	".docker":     true,
	".aws":        true,
	".azure":      true,
	".gcloud":     true,
	".npmrc":      true,
	".pypirc":     true,
	".gem":        true,
	".cargo":      true,
}

// sensitiveLocalFiles lists filenames that should be protected from SFTP writes.
var sensitiveLocalFiles = map[string]bool{
	".bashrc":       true,
	".bash_profile": true,
	".zshrc":        true,
	".profile":      true,
	".gitconfig":    true,
	".netrc":        true,
	".env":          true,
	"id_rsa":        true,
	"id_ed25519":    true,
	"authorized_keys": true,
	"known_hosts":   true,
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

	// Resolve symlinks to prevent symlink-based bypass
	resolved, err := filepath.EvalSymlinks(filepath.Dir(cleaned))
	if err == nil {
		cleaned = filepath.Join(resolved, filepath.Base(cleaned))
	}

	// Check each component of the path for sensitive directories
	parts := strings.Split(filepath.ToSlash(cleaned), "/")
	for _, part := range parts {
		if sensitiveLocalDirs[part] {
			return fmt.Errorf("refusing to write to sensitive directory %q in path: %s", part, path)
		}
	}

	// Check filename
	baseName := filepath.Base(cleaned)
	if sensitiveLocalFiles[baseName] {
		return fmt.Errorf("refusing to write to sensitive file: %s", baseName)
	}

	return nil
}

// isDangerousPath checks if a remote path is too dangerous for recursive delete.
func isDangerousPath(remotePath string) bool {
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
