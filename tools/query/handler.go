// Package query reads one value out of a JSON, YAML or TOML file by a
// dot-notation path, so an agent does not load a large config into context.
package query

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agent-tool/common"

	"github.com/BurntSushi/toml"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

type QueryInput struct {
	FilePath       string `json:"file_path,omitempty" jsonschema:"JSON, YAML or TOML file. Relative paths use workspace/MCP root"`
	Path           string `json:"path,omitempty" jsonschema:"Alias for file_path"`
	Query          string `json:"query" jsonschema:"Dot-notation path (e.g. dependencies.react, services.web.ports[0], servers[*].host)"`
	Format         string `json:"format,omitempty" jsonschema:"json, yaml or toml. Default: from the extension (.json, .yaml/.yml, .toml)"`
	MaxOutputChars int    `json:"max_output_chars,omitempty" jsonschema:"Maximum returned text characters. Default: 32768, Max: 131072"`
}

type QueryOutput struct {
	Result    string `json:"result"`
	Truncated bool   `json:"truncated"`
}

// Parsed documents take 5-20x their file size in memory, so the cap is
// stricter than the general file size setting.
const maxDocSize = 10 * 1024 * 1024

func Handle(ctx context.Context, req *mcp.CallToolRequest, input QueryInput) (*mcp.CallToolResult, QueryOutput, error) {
	if input.FilePath == "" {
		input.FilePath = input.Path
	}
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	resolvedPath, err := common.ResolveRequestPath(ctx, req, input.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot resolve file_path: %v", err))
	}
	input.FilePath = resolvedPath
	if strings.TrimSpace(input.Query) == "" {
		return errorResult("query is required")
	}
	format, err := detectFormat(input.FilePath, input.Format)
	if err != nil {
		return errorResult(err.Error())
	}

	if !common.GetAllowSymlinks() {
		if lfi, err := os.Lstat(input.FilePath); err == nil && lfi.Mode()&os.ModeSymlink != 0 {
			return errorResult("symlinks are not allowed (see set_config allow_symlinks)")
		}
	}
	fi, err := os.Stat(input.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", input.FilePath))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}
	if fi.IsDir() {
		return errorResult("path is a directory, not a file")
	}
	maxSize := min(int64(common.GetMaxFileSize()), maxDocSize)
	if fi.Size() > maxSize {
		return errorResult(fmt.Sprintf("file too large: %d bytes (max: %d bytes); parsing takes 5-20x the file size in memory. Use grep or read with offset instead", fi.Size(), maxSize))
	}
	data, err := os.ReadFile(input.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot read file: %v", err))
	}
	// All three formats are UTF-8 by spec; editors on Windows still add a BOM.
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

	root, err := parse(format, data)
	if err != nil {
		return errorResult(fmt.Sprintf("invalid %s: %v", strings.ToUpper(format), err))
	}
	result, err := common.Navigate(root, input.Query)
	if err != nil {
		return errorResult(fmt.Sprintf("query error: %v", err))
	}

	msg := fmt.Sprintf("File: %s\nQuery: %s\nType: %s\n\n%s",
		filepath.Base(input.FilePath), input.Query, common.TypeName(result), formatValue(result))
	maxOutputChars := input.MaxOutputChars
	if maxOutputChars <= 0 {
		maxOutputChars = common.DefaultOutputChars
	}
	if maxOutputChars > common.HardOutputChars {
		return errorResult(fmt.Sprintf("max_output_chars must be at most %d", common.HardOutputChars))
	}
	msg, truncated := common.TruncateRunes(msg, maxOutputChars,
		"\n[truncated=true; refine the query or select a narrower array/object path]")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, QueryOutput{Result: msg, Truncated: truncated}, nil
}

func detectFormat(path, explicit string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(explicit))
	if f == "" {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json":
			f = "json"
		case ".yaml", ".yml":
			f = "yaml"
		case ".toml":
			f = "toml"
		default:
			return "", fmt.Errorf("cannot tell the format of %s from its extension; pass format=json, yaml or toml", filepath.Base(path))
		}
	}
	switch f {
	case "json", "yaml", "toml":
		return f, nil
	case "yml":
		return "yaml", nil
	}
	return "", fmt.Errorf("unknown format %q: use json, yaml or toml", explicit)
}

// parse decodes data into the map/slice shapes common.Navigate walks:
// map[string]interface{} and []interface{}.
func parse(format string, data []byte) (interface{}, error) {
	var root interface{}
	switch format {
	case "json":
		err := json.Unmarshal(data, &root)
		return root, err
	case "yaml":
		if err := yaml.Unmarshal(data, &root); err != nil {
			return nil, err
		}
		return normalize(root), nil
	default:
		var m map[string]interface{}
		if _, err := toml.Decode(string(data), &m); err != nil {
			return nil, err
		}
		return normalize(m), nil
	}
}

// normalize converts what the YAML and TOML decoders produce besides
// Navigate's shapes: YAML maps with non-string keys, and TOML's typed slices
// ([]int64, []string, []map[string]interface{} for [[tables]], ...).
func normalize(v interface{}) interface{} {
	switch val := v.(type) {
	case map[interface{}]interface{}:
		m := make(map[string]interface{}, len(val))
		for k, v2 := range val {
			m[fmt.Sprintf("%v", k)] = normalize(v2)
		}
		return m
	case map[string]interface{}:
		for k, v2 := range val {
			val[k] = normalize(v2)
		}
		return val
	case []interface{}:
		for i, v2 := range val {
			val[i] = normalize(v2)
		}
		return val
	case []map[string]interface{}:
		return toIface(val, func(m map[string]interface{}) interface{} { return normalize(m) })
	case []int64:
		return toIface(val, nil)
	case []string:
		return toIface(val, nil)
	case []float64:
		return toIface(val, nil)
	case []bool:
		return toIface(val, nil)
	case []time.Time:
		return toIface(val, nil)
	}
	return v
}

func toIface[T any](s []T, conv func(T) interface{}) []interface{} {
	out := make([]interface{}, len(s))
	for i, v := range s {
		if conv != nil {
			out[i] = conv(v)
		} else {
			out[i] = v
		}
	}
	return out
}

func formatValue(v interface{}) string {
	switch x := v.(type) {
	case string:
		return fmt.Sprintf("%q", x)
	case nil:
		return "null"
	case int64, int:
		return fmt.Sprintf("%d", x)
	case time.Time:
		return x.Format(time.RFC3339)
	}
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(pretty)
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "query",
		Description: `Read one value from a JSON, YAML or TOML file by a dot-notation path, without loading the whole file into context.
Format comes from the extension (.json, .yaml/.yml, .toml); pass format for other names.
Supports nested keys (a.b.c), array indices ([0], [-1] for last) and wildcards ([*]).
Examples: "scripts.build", "services.web.ports[0]", "tool.poetry.name", "users[*].email".
Returns the value with its type; objects and arrays print as JSON. Output defaults to 32768 characters and reports truncation.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, QueryOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, QueryOutput{}, nil
}
