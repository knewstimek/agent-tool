package ssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"agent-tool/common"
	"agent-tool/internal/vault"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type profileSearchInput struct {
	Query   string `json:"query,omitempty" jsonschema:"Words to match across profile names, aliases, descriptions, and tags. Omit to list profiles."`
	Kind    string `json:"kind,omitempty" jsonschema:"Filter by ssh, sftp, mysql, cloudflare, or aws."`
	Storage string `json:"storage,omitempty" jsonschema:"Filter by vault or legacy. By default encrypted vault profiles appear first."`
	Limit   int    `json:"limit,omitempty" jsonschema:"Maximum results per page, default 20, up to 100."`
	Offset  int    `json:"offset,omitempty" jsonschema:"Use the previous next_offset with the same query to continue."`
}

type profileSearchMetadata = vault.Metadata

type profileSearchMatch struct {
	ConnectionProfile string `json:"connection_profile"`
	Kind              string `json:"kind"`
	Storage           string `json:"storage"`
	Revision          int64  `json:"revision,omitempty"`
	profileSearchMetadata
}

type profileSearchOutput struct {
	Profiles   []profileSearchMatch `json:"profiles"`
	Total      int                  `json:"total"`
	NextOffset int                  `json:"next_offset,omitempty"`
	Warnings   []string             `json:"warnings,omitempty"`
}

const (
	storageVault  = "vault"
	storageLegacy = "legacy"
)

func RegisterProfileSearch(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name:        "profile_search",
		Description: "Find SSH/SFTP, MySQL, Cloudflare, or AWS profiles. Encrypted vault profiles appear first. Pass a result's connection_profile to the matching tool.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, handleProfileSearch)
}

func handleProfileSearch(ctx context.Context, _ *mcp.CallToolRequest, input profileSearchInput) (*mcp.CallToolResult, profileSearchOutput, error) {
	limit := input.Limit
	if limit == 0 {
		limit = 20
	}
	if limit < 0 || limit > 100 || input.Offset < 0 {
		return nil, profileSearchOutput{}, fmt.Errorf("use a limit between 1 and 100 and a nonnegative offset")
	}
	kind := strings.ToLower(strings.TrimSpace(input.Kind))
	if kind == "sftp" {
		kind = vault.SSH
	}
	switch kind {
	case "", vault.SSH, vault.MySQL, vault.Cloudflare, vault.AWS:
	default:
		return nil, profileSearchOutput{}, fmt.Errorf("kind must be ssh, sftp, mysql, cloudflare, or aws")
	}
	storage := strings.ToLower(strings.TrimSpace(input.Storage))
	if storage != "" && storage != storageVault && storage != storageLegacy {
		return nil, profileSearchOutput{}, fmt.Errorf("storage must be vault or legacy")
	}
	profiles, warnings, err := discoverProfiles(ctx, kind, storage)
	if err != nil {
		return nil, profileSearchOutput{}, err
	}

	query := strings.ToLower(strings.TrimSpace(input.Query))
	terms := strings.Fields(query)
	type rankedMatch struct {
		match profileSearchMatch
		rank  int
	}
	matches := make([]rankedMatch, 0)
	for _, profile := range profiles {
		name, metadata := profile.ConnectionProfile, profile.profileSearchMetadata
		fields := []string{strings.ToLower(name), strings.ToLower(metadata.Description)}
		for _, values := range [][]string{metadata.Aliases, metadata.Tags} {
			for _, value := range values {
				fields = append(fields, strings.ToLower(value))
			}
		}
		if slices.ContainsFunc(terms, func(term string) bool {
			return !slices.ContainsFunc(fields, func(field string) bool { return strings.Contains(field, term) })
		}) {
			continue
		}
		rank := 2
		switch {
		case query != "" && strings.EqualFold(name, query):
			rank = 0
		case query != "" && slices.ContainsFunc(metadata.Aliases, func(alias string) bool { return strings.EqualFold(alias, query) }):
			rank = 1
		}
		matches = append(matches, rankedMatch{profile, rank})
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].match.Storage != matches[j].match.Storage {
			return matches[i].match.Storage == storageVault
		}
		if matches[i].rank != matches[j].rank {
			return matches[i].rank < matches[j].rank
		}
		if matches[i].match.ConnectionProfile == matches[j].match.ConnectionProfile {
			return matches[i].match.Kind < matches[j].match.Kind
		}
		return matches[i].match.ConnectionProfile < matches[j].match.ConnectionProfile
	})

	start := min(input.Offset, len(matches))
	end := start + min(limit, len(matches)-start)
	output := profileSearchOutput{
		Profiles: make([]profileSearchMatch, 0, end-start), Total: len(matches), Warnings: warnings,
	}
	envelope, err := json.Marshal(output)
	if err != nil {
		return nil, profileSearchOutput{}, err
	}
	remaining := common.DefaultOutputChars - len(envelope) - 64
	for _, entry := range matches[start:end] {
		row, err := json.Marshal(entry.match)
		if err != nil {
			return nil, profileSearchOutput{}, err
		}
		if len(row)+1 > remaining {
			if len(output.Profiles) == 0 {
				return nil, profileSearchOutput{}, fmt.Errorf("profile metadata is too large to return; shorten its description, aliases, or tags")
			}
			break
		}
		remaining -= len(row) + 1
		output.Profiles = append(output.Profiles, entry.match)
	}
	if next := start + len(output.Profiles); next < len(matches) {
		output.NextOffset = next
	}
	data, err := json.Marshal(output)
	if err != nil {
		return nil, profileSearchOutput{}, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}}, output, nil
}

func discoverProfiles(ctx context.Context, kind, storage string) ([]profileSearchMatch, []string, error) {
	legacyKind := kind == "" || kind == vault.SSH
	if storage == storageLegacy && !legacyKind {
		return nil, nil, nil
	}
	vaultProfiles, vaultAvailable, vaultErr := readVaultProfileCatalog(ctx, kind)
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	var found []profileSearchMatch
	shadowed := make(map[string]bool)
	for _, p := range vaultProfiles {
		if p.Kind == vault.SSH {
			shadowed[p.Name] = true
		}
		if storage != storageLegacy && !p.Removed {
			found = append(found, profileSearchMatch{
				ConnectionProfile: p.Name, Kind: p.Kind, Storage: storageVault, Revision: p.Revision, profileSearchMetadata: p.Metadata,
			})
		}
	}
	if !legacyKind || storage == storageVault {
		return found, nil, vaultErr
	}
	legacy, _, err := readLocalConnectionProfiles()
	if err != nil && (!errors.Is(err, os.ErrNotExist) || strings.TrimSpace(os.Getenv("AGENT_TOOL_CONNECTION_PROFILE_FILE")) != "") {
		legacyErr := fmt.Errorf("cannot load local connection profiles; check that the configured file exists, is readable, and contains valid profile JSON")
		if !vaultAvailable || storage == storageLegacy {
			return nil, nil, errors.Join(legacyErr, vaultErr)
		}
		return found, []string{legacyErr.Error()}, nil
	}
	for name, p := range legacy {
		if name != "" && name == strings.TrimSpace(name) && !shadowed[name] {
			found = append(found, profileSearchMatch{
				ConnectionProfile: name, Kind: vault.SSH, Storage: storageLegacy, profileSearchMetadata: p.searchMetadata,
			})
		}
	}
	if vaultErr != nil {
		if err != nil {
			return nil, nil, vaultErr
		}
		return found, []string{vaultErr.Error() + "; SSH profile names may not resolve until the vault is readable"}, nil
	}
	return found, nil, nil
}

func readVaultProfileCatalog(ctx context.Context, kind string) ([]vault.Profile, bool, error) {
	store, err := vault.Open()
	if errors.Is(err, vault.ErrUninitialized) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("cannot read vault profile catalog")
	}
	defer store.Close()
	profiles, err := store.Profiles(ctx, kind, true)
	if err != nil {
		return nil, false, fmt.Errorf("cannot read vault profile catalog")
	}
	return profiles, true, nil
}
