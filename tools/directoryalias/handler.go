package directoryalias

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/ssh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Input struct {
	Operation         string            `json:"operation" jsonschema:"set, list, or delete,required"`
	Aliases           map[string]string `json:"aliases,omitempty" jsonschema:"Directory name-to-path map for set; max 64. Local values resolve against workspace; remote values must be absolute"`
	Names             []string          `json:"names,omitempty" jsonschema:"Names to delete or filter when listing"`
	Overwrite         bool              `json:"overwrite,omitempty" jsonschema:"Allow changing an existing binding; default false"`
	ConnectionProfile string            `json:"connection_profile,omitempty" jsonschema:"Remote connection profile; omit both connection fields for local workspace aliases"`
	ConnectionID      string            `json:"connection_id,omitempty" jsonschema:"Remote connection ID; aliases are isolated by client session and connection identity"`
}

type Output struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, in Input) (*mcp.CallToolResult, Output, error) {
	fail := func(err error) (*mcp.CallToolResult, Output, error) {
		message := err.Error()
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: message}}}, Output{Result: message}, nil
	}
	if in.Operation != "set" && in.Operation != "list" && in.Operation != "delete" {
		return fail(fmt.Errorf("operation must be set, list, or delete"))
	}
	if len(in.Aliases) > common.MaxDirectoryAliases || len(in.Names) > common.MaxDirectoryAliases {
		return fail(fmt.Errorf("at most 64 aliases per call"))
	}
	if in.Operation != "set" && len(in.Aliases) > 0 || in.Operation == "set" && len(in.Names) > 0 {
		return fail(fmt.Errorf("aliases is for set; names is for list/delete"))
	}
	scope := common.LocalAliasScope(ctx, req)
	remote := in.ConnectionProfile != "" || in.ConnectionID != ""
	if remote {
		var err error
		scope, err = ssh.ResolveDirectoryAliasScope(in.ConnectionProfile, in.ConnectionID)
		if err != nil {
			return fail(err)
		}
	}
	if in.Operation == "set" {
		if len(in.Aliases) == 0 {
			return fail(fmt.Errorf("aliases is required for set"))
		}
		normalized := make(map[string]string, len(in.Aliases))
		for name, p := range in.Aliases {
			if !common.ValidDirectoryAliasName(name) || strings.HasPrefix(p, "@") {
				return fail(fmt.Errorf("invalid alias name or nested target: %q", name))
			}
			if remote {
				var err error
				p, err = ssh.NormalizeRemoteDirectory(p)
				if err != nil {
					return fail(err)
				}
			} else {
				resolved, err := common.ResolveRequestPath(ctx, req, p)
				if err != nil {
					return fail(err)
				}
				info, err := os.Stat(resolved)
				if err != nil {
					return fail(fmt.Errorf("alias %q directory: %w", name, err))
				}
				if !info.IsDir() {
					return fail(fmt.Errorf("alias %q target is not a directory", name))
				}
				p = resolved
			}
			normalized[name] = p
		}
		if err := common.UpdateDirectoryAliases(ctx, req, scope, normalized, nil, in.Overwrite); err != nil {
			return fail(err)
		}
	} else if in.Operation == "delete" {
		if len(in.Names) == 0 {
			return fail(fmt.Errorf("names is required for delete"))
		}
		if err := common.UpdateDirectoryAliases(ctx, req, scope, nil, in.Names, false); err != nil {
			return fail(err)
		}
	}
	message := "OK"
	if in.Operation == "list" {
		aliases := common.DirectoryAliasMap(ctx, req, scope)
		if len(in.Names) > 0 {
			filtered := make(map[string]string, len(in.Names))
			for _, name := range in.Names {
				p, ok := aliases[name]
				if !ok {
					return fail(fmt.Errorf("directory alias %q not found", name))
				}
				filtered[name] = p
			}
			aliases = filtered
		}
		encoded, err := json.Marshal(aliases)
		if err != nil {
			return fail(err)
		}
		if len(encoded) > common.DefaultOutputChars {
			return fail(fmt.Errorf("alias list too large; filter with names"))
		}
		message = string(encoded)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: message}}}, Output{Result: message}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{Name: "directory_alias", Description: "Manage session-only directory aliases: set a name-to-directory map, list on demand, or delete names. Use @name/subpath in structured path arguments. Local aliases are workspace-scoped; remote aliases require connection_profile or connection_id and are target-scoped. No files are created and SSH command text is never substituted."}, Handle)
}
