package common

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const MaxDirectoryAliases = 64

type aliasSessionKey struct {
	session  *mcp.ServerSession
	fallback string
}

var directoryAliases = struct {
	sync.RWMutex
	sessions map[aliasSessionKey]map[string]map[string]string
}{sessions: make(map[aliasSessionKey]map[string]map[string]string)}

func aliasKey(ctx context.Context, req *mcp.CallToolRequest) aliasSessionKey {
	if req != nil && req.Session != nil {
		return aliasSessionKey{session: req.Session}
	}
	return aliasSessionKey{fallback: RequestWorkspace(ctx, req)}
}

func LocalAliasScope(ctx context.Context, req *mcp.CallToolRequest) string {
	return "local:" + RequestWorkspace(ctx, req)
}

// DirectoryAliasMap returns a snapshot, never mutable registry state.
func DirectoryAliasMap(ctx context.Context, req *mcp.CallToolRequest, scope string) map[string]string {
	key := aliasKey(ctx, req)
	directoryAliases.RLock()
	defer directoryAliases.RUnlock()
	result := make(map[string]string)
	for name, p := range directoryAliases.sessions[key][scope] {
		result[name] = p
	}
	return result
}

func ValidDirectoryAliasName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for i, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '-')) {
			return false
		}
	}
	return true
}

// UpdateDirectoryAliases validates and replaces a scope atomically. Identical
// registrations are idempotent; changing a live binding requires overwrite.
func UpdateDirectoryAliases(ctx context.Context, req *mcp.CallToolRequest, scope string, updates map[string]string, remove []string, overwrite bool) error {
	if len(updates) > MaxDirectoryAliases || len(remove) > MaxDirectoryAliases {
		return fmt.Errorf("at most %d aliases per operation", MaxDirectoryAliases)
	}
	for name, p := range updates {
		if !ValidDirectoryAliasName(name) || p == "" || len(p) > 4096 || strings.ContainsAny(p, "\x00\r\n") {
			return fmt.Errorf("invalid directory alias %q", name)
		}
	}
	key := aliasKey(ctx, req)
	directoryAliases.Lock()
	defer directoryAliases.Unlock()
	scopes := directoryAliases.sessions[key]
	current := scopes[scope]
	next := make(map[string]string, len(current)+len(updates))
	for name, p := range current {
		next[name] = p
	}
	for _, name := range remove {
		if !ValidDirectoryAliasName(name) {
			return fmt.Errorf("invalid alias name %q", name)
		}
		if _, ok := next[name]; !ok {
			return fmt.Errorf("directory alias %q not found", name)
		}
		delete(next, name)
	}
	for name, p := range updates {
		if old, ok := next[name]; ok && old != p && !overwrite {
			return fmt.Errorf("directory alias %q already exists; use overwrite=true", name)
		}
		next[name] = p
	}
	if len(next) > MaxDirectoryAliases {
		return fmt.Errorf("at most %d aliases per scope", MaxDirectoryAliases)
	}
	if len(next) == 0 {
		delete(scopes, scope)
		// Keep real-session entries until Wait completes: one cleanup waiter per session.
		if len(scopes) == 0 && key.session == nil {
			delete(directoryAliases.sessions, key)
		}
		return nil
	}
	if scopes == nil {
		if len(directoryAliases.sessions) >= 256 {
			return fmt.Errorf("directory alias session limit reached")
		}
		scopes = make(map[string]map[string]string)
		directoryAliases.sessions[key] = scopes
		if key.session != nil {
			go func() {
				_ = key.session.Wait()
				directoryAliases.Lock()
				delete(directoryAliases.sessions, key)
				directoryAliases.Unlock()
			}()
		}
	}
	if _, ok := scopes[scope]; !ok && len(scopes) >= 64 {
		return fmt.Errorf("directory alias scope limit reached")
	}
	scopes[scope] = next
	return nil
}

// ExpandDirectoryAlias only handles structured path arguments. Absolute paths
// and ./@literal remain ordinary paths. Alias suffixes cannot escape their base.
func ExpandDirectoryAlias(aliases map[string]string, p string, join func(string, string) string) (string, error) {
	if !strings.HasPrefix(p, "@") {
		return p, nil
	}
	token := p[1:]
	name, tail := token, ""
	if i := strings.IndexAny(token, "/\\"); i >= 0 {
		name, tail = token[:i], token[i+1:]
	}
	if !ValidDirectoryAliasName(name) {
		return "", fmt.Errorf("invalid directory alias reference")
	}
	base, ok := aliases[name]
	if !ok {
		return "", fmt.Errorf("directory alias %q not found in this session/target", name)
	}
	if strings.HasPrefix(tail, "/") || strings.HasPrefix(tail, "\\") || strings.ContainsAny(tail, ":\x00\r\n") {
		return "", fmt.Errorf("alias suffix must be a relative path")
	}
	for _, part := range strings.FieldsFunc(tail, func(c rune) bool { return c == '/' || c == '\\' }) {
		if part == ".." {
			return "", fmt.Errorf("alias suffix cannot contain ..")
		}
	}
	if tail == "" {
		return base, nil
	}
	return join(base, tail), nil
}

func DisplayPathWithAliases(root, p string, aliases map[string]string) string {
	return DisplayDirectoryAliases(p, DisplayPath(root, p), aliases, DisplayPath)
}

func DisplayDirectoryAliases(p, best string, aliases map[string]string, relative func(string, string) string) string {
	// An ordinary filename must not become an alias when copied into the next call.
	if strings.HasPrefix(best, "@") {
		best = "./" + best
	}
	names := make([]string, 0, len(aliases))
	for name := range aliases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rel := relative(aliases[name], p)
		if filepath.IsAbs(rel) || rel == p {
			continue
		}
		candidate := "@" + name
		if rel != "." {
			candidate += "/" + rel
		}
		// Some legal filesystem names (e.g. POSIX ':') cannot be expressed
		// with our intentionally stricter alias syntax.
		if _, err := ExpandDirectoryAlias(aliases, candidate, func(_, tail string) string { return tail }); err != nil {
			continue
		}
		if len(candidate) < len(best) {
			best = candidate
		}
	}
	return best
}
