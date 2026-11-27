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

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type profileSearchInput struct {
	Query  string `json:"query,omitempty" jsonschema:"Words to match across profile names, aliases, descriptions, and tags. Omit to list profiles."`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum results per page, default 20, up to 100."`
	Offset int    `json:"offset,omitempty" jsonschema:"Use the previous next_offset with the same query to continue."`
}

type profileSearchMetadata struct {
	Description string   `json:"description,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type profileSearchMatch struct {
	ConnectionProfile string `json:"connection_profile"`
	profileSearchMetadata
}

type profileSearchOutput struct {
	Profiles   []profileSearchMatch `json:"profiles"`
	Total      int                  `json:"total"`
	NextOffset int                  `json:"next_offset,omitempty"`
}

func RegisterProfileSearch(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name:        "profile_search",
		Description: "Find local SSH/SFTP connection profiles by name, alias, description, or tag. Pass a result's connection_profile to ssh or sftp.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, handleProfileSearch)
}

func handleProfileSearch(_ context.Context, _ *mcp.CallToolRequest, input profileSearchInput) (*mcp.CallToolResult, profileSearchOutput, error) {
	limit := input.Limit
	if limit == 0 {
		limit = 20
	}
	if limit < 0 || limit > 100 || input.Offset < 0 {
		return nil, profileSearchOutput{}, fmt.Errorf("use a limit between 1 and 100 and a nonnegative offset")
	}
	profiles, _, err := readLocalConnectionProfiles()
	explicitFile := strings.TrimSpace(os.Getenv("AGENT_TOOL_CONNECTION_PROFILE_FILE")) != ""
	if err != nil && (!errors.Is(err, os.ErrNotExist) || explicitFile) {
		return nil, profileSearchOutput{}, fmt.Errorf("cannot load local connection profiles; check that the configured file exists, is readable, and contains valid profile JSON")
	}

	query := strings.ToLower(strings.TrimSpace(input.Query))
	terms := strings.Fields(query)
	type rankedMatch struct {
		match profileSearchMatch
		rank  int
	}
	matches := make([]rankedMatch, 0)
	for name, profile := range profiles {
		if name == "" || strings.TrimSpace(name) != name {
			continue
		}
		metadata := profile.searchMetadata
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
		matches = append(matches, rankedMatch{profileSearchMatch{name, metadata}, rank})
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].rank != matches[j].rank {
			return matches[i].rank < matches[j].rank
		}
		return matches[i].match.ConnectionProfile < matches[j].match.ConnectionProfile
	})

	start := min(input.Offset, len(matches))
	end := start + min(limit, len(matches)-start)
	output := profileSearchOutput{Profiles: make([]profileSearchMatch, 0, end-start), Total: len(matches)}
	remaining := common.DefaultOutputChars - 128 // Reserve space for the page envelope.
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
