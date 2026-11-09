package common

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectoryAliasBoundariesAndDeterministicDisplay(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "very", "deep", "directory")
	aliases := map[string]string{"src": base, "aaa": base}
	got, err := ExpandDirectoryAlias(aliases, "@src/a/b.txt", func(base, tail string) string { return filepath.Join(base, tail) })
	if err != nil || got != filepath.Join(base, "a", "b.txt") {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if got := DisplayPathWithAliases(root, got, aliases); got != "@aaa/a/b.txt" {
		t.Fatal(got)
	}
	neighbor := base + "-other"
	if got := DisplayPathWithAliases(root, neighbor, aliases); strings.HasPrefix(got, "@") {
		t.Fatal("prefix collision")
	}
	for _, bad := range []string{"@", "@src/..", "@src/a/../b", "@src//etc", "@src/\\etc", "@src/D:/x", "@src/x:stream", "@src/\x00"} {
		if _, err := ExpandDirectoryAlias(aliases, bad, func(a, b string) string { return filepath.Join(a, b) }); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if got, err := ExpandDirectoryAlias(aliases, "./@literal", func(a, b string) string { return filepath.Join(a, b) }); err != nil || got != "./@literal" {
		t.Fatal(got, err)
	}
}

func TestDirectoryAliasDisplayCanBeReused(t *testing.T) {
	root := t.TempDir()
	literal := filepath.Join(root, "@literal", "file.txt")
	if got := DisplayPathWithAliases(root, literal, nil); got != "./@literal/file.txt" {
		t.Errorf("literal path looks like an alias: %q", got)
	}
	displayLiteral := DisplayPathWithAliases(root, literal, map[string]string{"literal": filepath.Join(root, "somewhere-else")})
	expanded, err := ExpandDirectoryAlias(map[string]string{"literal": filepath.Join(root, "somewhere-else")}, displayLiteral, func(a, b string) string { return filepath.Join(a, b) })
	if err != nil || filepath.Join(root, expanded) != literal {
		t.Fatalf("literal redirected: %q %v", expanded, err)
	}
	base := filepath.Join(root, "very", "deep", "directory")
	aliases := map[string]string{"src": base}
	file := filepath.Join(base, "file:stream")
	display := DisplayPathWithAliases(root, file, aliases)
	if _, err := ExpandDirectoryAlias(aliases, display, func(a, b string) string { return filepath.Join(a, b) }); err != nil {
		t.Errorf("emitted an unusable alias %q: %v", display, err)
	}
}
