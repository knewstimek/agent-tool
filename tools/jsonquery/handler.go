package jsonquery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type JSONQueryInput struct {
	FilePath string `json:"file_path" jsonschema:"Absolute path to the JSON file"`
	Query    string `json:"query" jsonschema:"Dot-notation query path (e.g. dependencies.react, items[0].name, items[*].id)"`
}

type JSONQueryOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input JSONQueryInput) (*mcp.CallToolResult, JSONQueryOutput, error) {
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	if !filepath.IsAbs(input.FilePath) {
		return errorResult("file_path must be an absolute path")
	}
	if strings.TrimSpace(input.Query) == "" {
		return errorResult("query is required")
	}

	// Symlink check
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

	// Size check — JSON parsing inflates memory 5-20x vs raw file size,
	// so use a stricter limit than the general file size setting.
	const maxJSONSize = 10 * 1024 * 1024 // 10 MB
	maxSize := int64(common.GetMaxFileSize())
	if maxSize > maxJSONSize {
		maxSize = maxJSONSize
	}
	if fi.Size() > maxSize {
		return errorResult(fmt.Sprintf("file too large: %d bytes (max: %d bytes). JSON parsing uses 5-20x more memory than file size", fi.Size(), maxSize))
	}

	data, err := os.ReadFile(input.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot read file: %v", err))
	}

	// Parse JSON
	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return errorResult(fmt.Sprintf("invalid JSON: %v", err))
	}

	// Navigate query path
	result, err := navigate(root, input.Query)
	if err != nil {
		return errorResult(fmt.Sprintf("query error: %v", err))
	}

	// Format output
	typeName := jsonTypeName(result)
	var valueStr string
	switch v := result.(type) {
	case string:
		valueStr = fmt.Sprintf("%q", v)
	case nil:
		valueStr = "null"
	default:
		pretty, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			valueStr = fmt.Sprintf("%v", result)
		} else {
			valueStr = string(pretty)
		}
	}

	msg := fmt.Sprintf("File: %s\nQuery: %s\nType: %s\n\n%s",
		filepath.Base(input.FilePath), input.Query, typeName, valueStr)

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, JSONQueryOutput{Result: msg}, nil
}

// navigate walks the JSON tree following the dot-notation query path.
func navigate(data interface{}, query string) (interface{}, error) {
	parts := parsePath(query)
	current := data

	for pi, part := range parts {
		if part.isWildcard {
			// Wildcard [*] — collect field from all array elements
			arr, ok := current.([]interface{})
			if !ok {
				return nil, fmt.Errorf("cannot apply [*] to %s (expected array)", jsonTypeName(current))
			}
			var results []interface{}
			// Use actual slice index instead of stored part.index
			// to correctly handle nested wildcards across recursive calls
			remaining := buildRemainingPath(parts, pi)
			for i, item := range arr {
				if remaining == "" {
					results = append(results, item)
				} else {
					val, err := navigate(item, remaining)
					if err != nil {
						return nil, fmt.Errorf("[%d].%s: %v", i, remaining, err)
					}
					results = append(results, val)
				}
			}
			return results, nil
		}

		if part.isIndex {
			arr, ok := current.([]interface{})
			if !ok {
				return nil, fmt.Errorf("cannot index %s with [%d] (expected array)", jsonTypeName(current), part.arrayIdx)
			}
			idx := part.arrayIdx
			if idx < 0 {
				idx = len(arr) + idx // negative index from end
			}
			if idx < 0 || idx >= len(arr) {
				return nil, fmt.Errorf("array index %d out of range (length %d)", part.arrayIdx, len(arr))
			}
			current = arr[idx]
			continue
		}

		// Object key access
		obj, ok := current.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("cannot access key %q on %s (expected object)", part.key, jsonTypeName(current))
		}
		val, exists := obj[part.key]
		if !exists {
			return nil, fmt.Errorf("key %q not found", part.key)
		}
		current = val
	}

	return current, nil
}

type pathPart struct {
	key        string
	isIndex    bool
	arrayIdx   int
	isWildcard bool
}

// parsePath splits "items[0].name" into [{key:"items"}, {isIndex:true, arrayIdx:0}, {key:"name"}]
func parsePath(query string) []pathPart {
	var parts []pathPart
	i := 0
	query = strings.TrimSpace(query)

	for i < len(query) {
		if query[i] == '.' {
			i++
			continue
		}

		if query[i] == '[' {
			// Find closing bracket
			end := strings.IndexByte(query[i:], ']')
			if end == -1 {
				parts = append(parts, pathPart{key: query[i:]})
				break
			}
			inner := query[i+1 : i+end]
			if inner == "*" {
				parts = append(parts, pathPart{isWildcard: true})
			} else {
				idx, err := strconv.Atoi(inner)
				if err != nil {
					parts = append(parts, pathPart{key: inner})
				} else {
					parts = append(parts, pathPart{isIndex: true, arrayIdx: idx})
				}
			}
			i += end + 1
			continue
		}

		// Read key until . or [
		end := i
		for end < len(query) && query[end] != '.' && query[end] != '[' {
			end++
		}
		parts = append(parts, pathPart{key: query[i:end]})
		i = end
	}

	return parts
}

// buildRemainingPath reconstructs the query path after a wildcard part.
func buildRemainingPath(parts []pathPart, wildcardIdx int) string {
	remaining := parts[wildcardIdx+1:]
	if len(remaining) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, p := range remaining {
		if i > 0 && !p.isIndex && !p.isWildcard {
			sb.WriteByte('.')
		}
		if p.isWildcard {
			sb.WriteString("[*]")
		} else if p.isIndex {
			sb.WriteString(fmt.Sprintf("[%d]", p.arrayIdx))
		} else {
			sb.WriteString(p.key)
		}
	}
	return sb.String()
}

func jsonTypeName(v interface{}) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "jsonquery",
		Description: `Query a JSON file using dot-notation paths without loading the entire file into context.
Supports nested keys (a.b.c), array indices ([0], [-1] for last), and wildcards ([*] for all elements).
Examples: "dependencies.react", "scripts.build", "items[0].name", "users[*].email".
Returns the matched value with its type. Objects and arrays are pretty-printed.
Use this to extract specific values from large JSON files to save tokens.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, JSONQueryOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, JSONQueryOutput{}, nil
}
