package ssh

import (
	"strings"
	"testing"

	"agent-tool/common"
)

func TestAliasScopeUsesEffectiveConnectionDefaults(t *testing.T) {
	implicit := SSHInput{Host: "example.invalid", User: "builder"}
	explicit := SSHInput{Host: "example.invalid", User: "builder", Port: 22, HostKeyCheck: "tofu", UseAgent: true}
	if ConnectionAliasScope(implicit) != ConnectionAliasScope(explicit) {
		t.Error("equivalent connection defaults produced different alias scopes")
	}
	jump := SSHInput{Host: "example.invalid", User: "builder", JumpHost: "jump.example.invalid"}
	normalized := jump
	if err := validateInput(&normalized); err != nil {
		t.Fatal(err)
	}
	if ConnectionAliasScope(jump) != ConnectionAliasScope(normalized) {
		t.Error("validation changed the alias namespace")
	}
	foreign := explicit
	foreign.Host = "other.example.invalid"
	if ConnectionAliasScope(explicit) == ConnectionAliasScope(foreign) {
		t.Error("different targets shared an alias namespace")
	}
}

func TestAliasDisplayRoundTripMatrix(t *testing.T) {
	count := 0
	for _, base := range []string{"/opt/very/deep/app", "/opt/@literal", "D:/very/deep/app", "D:/\u212Aroot/deep"} {
		aliases := map[string]string{"a": base, "longer": base}
		for _, tail := range []string{"file", "dir/file", "@literal", "a:b", "a\\b", " leading", "trailing ", "\uD55C\uAE00.txt", "a/../other", "..\\outside", "./file"} {
			actual := ResolveRemotePath(base, tail)
			for _, root := range []string{"/elsewhere", "/opt", base} {
				display := DisplayRemotePathWithAliases(root, actual, aliases)
				expanded, err := common.ExpandDirectoryAlias(aliases, display, ResolveRemotePath)
				if err != nil {
					t.Errorf("invalid emitted reference %q: %v", display, err)
					continue
				}
				resolved := ResolveRemotePath(root, expanded)
				same := resolved == actual
				if windowsRemotePath(actual) {
					same = strings.EqualFold(resolved, actual)
				}
				if !same {
					t.Errorf("root=%q original=%q display=%q resolved=%q", root, actual, display, resolved)
				}
				count++
			}
		}
	}
	if count != 132 {
		t.Fatalf("matrix incomplete: %d", count)
	}
}
