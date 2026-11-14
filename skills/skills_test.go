package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShippedSkillsAreWellFormed(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("no skills embedded")
	}
	for _, name := range names {
		// Remove deletes by name, so a shipped name must not be one a user
		// would pick for their own skill.
		if !strings.HasPrefix(name, "agent-tool-") {
			t.Errorf("skill %q lacks the agent-tool- prefix", name)
		}
		data, err := files.ReadFile(name + "/SKILL.md")
		if err != nil {
			t.Fatal(err)
		}
		// A checkout with autocrlf embeds CRLF; the format is the same.
		text := strings.ReplaceAll(string(data), "\r\n", "\n")
		if !strings.HasPrefix(text, "---\nname: "+name+"\ndescription: ") {
			t.Errorf("skill %s: frontmatter must open with name (matching its directory) and description", name)
		}
		// Agents load the description of every installed skill into each
		// session; the body is read only when the skill triggers.
		_, rest, _ := strings.Cut(text, "\ndescription: ")
		description, _, _ := strings.Cut(rest, "\n")
		if len(description) < 80 || len(description) > 600 {
			t.Errorf("skill %s: description is %d chars, want 80..600", name, len(description))
		}
		if len(text) > 8000 {
			t.Errorf("skill %s is %d chars; keep the workflow here and parameters in agent_tool_help", name, len(text))
		}
		for i := 0; i < len(text); i++ {
			if text[i] > 127 {
				t.Errorf("skill %s has non-ASCII text at byte %d", name, i)
				break
			}
		}
	}
}

func TestInstallRefreshAndRemove(t *testing.T) {
	dir := t.TempDir()
	own := filepath.Join(dir, "my-notes")
	if err := os.MkdirAll(own, 0o755); err != nil {
		t.Fatal(err)
	}
	if Present(dir) {
		t.Fatal("Present reported a skill in a directory holding only a user skill")
	}

	names, err := Install(dir)
	if err != nil || len(names) != len(Names()) {
		t.Fatalf("Install = %v, %v", names, err)
	}
	if !Present(dir) {
		t.Fatal("Present is false after Install")
	}
	target := filepath.Join(dir, names[0], "SKILL.md")
	want, _ := files.ReadFile(names[0] + "/SKILL.md")

	// An older copy on disk is replaced.
	if err := os.WriteFile(target, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(dir); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); string(got) != string(want) {
		t.Error("Install did not refresh an existing skill")
	}

	removed, err := Remove(dir)
	if err != nil || len(removed) != len(names) {
		t.Fatalf("Remove = %v, %v", removed, err)
	}
	if Present(dir) {
		t.Error("skill still present after Remove")
	}
	if _, err := os.Stat(own); err != nil {
		t.Error("Remove deleted a skill it does not ship")
	}
	if again, _ := Remove(dir); len(again) != 0 {
		t.Errorf("second Remove reported %v", again)
	}
}
