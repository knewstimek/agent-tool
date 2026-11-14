// Package skills carries the agent skills shipped with agent-tool. They are
// embedded so "agent-tool install --skills" works from a downloaded binary,
// and each skill is versioned with the tools it describes.
package skills

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Every skill is one directory holding a SKILL.md, the layout Claude Code and
// Codex both load from their user skills directory.
//
//go:embed */SKILL.md
var files embed.FS

// Names lists the shipped skills. Each name carries the agent-tool- prefix so
// that Remove cannot delete a skill the user wrote themselves.
func Names() []string {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

// Present reports whether any shipped skill is installed under dir.
func Present(dir string) bool {
	for _, name := range Names() {
		if _, err := os.Stat(filepath.Join(dir, name, "SKILL.md")); err == nil {
			return true
		}
	}
	return false
}

// Install writes every shipped skill under dir (the agent's user skills
// directory), replacing an older copy, and returns the installed names.
func Install(dir string) ([]string, error) {
	names := Names()
	for _, name := range names {
		data, err := files.ReadFile(name + "/SKILL.md")
		if err != nil {
			return nil, err
		}
		target := filepath.Join(dir, name)
		if err := os.MkdirAll(target, 0o755); err != nil {
			return nil, fmt.Errorf("cannot create %s: %w", target, err)
		}
		if err := os.WriteFile(filepath.Join(target, "SKILL.md"), data, 0o644); err != nil {
			return nil, fmt.Errorf("cannot write skill %s: %w", name, err)
		}
	}
	return names, nil
}

// Remove deletes the shipped skills from dir and returns the names that were
// present. Other skills in dir are left alone.
func Remove(dir string) ([]string, error) {
	var removed []string
	for _, name := range Names() {
		target := filepath.Join(dir, name)
		if _, err := os.Stat(target); err != nil {
			continue
		}
		if err := os.RemoveAll(target); err != nil {
			return removed, fmt.Errorf("cannot remove skill %s: %w", name, err)
		}
		removed = append(removed, name)
	}
	return removed, nil
}
