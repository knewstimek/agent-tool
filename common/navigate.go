package common

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PathPart represents a single segment of a dot-notation query path.
type PathPart struct {
	Key        string
	IsIndex    bool
	ArrayIdx   int
	IsWildcard bool
}

// Navigate walks a data tree (from JSON/YAML/TOML unmarshal) following a dot-notation query path.
// Supports nested keys (a.b.c), array indices ([0], [-1]), and wildcards ([*]).
func Navigate(data interface{}, query string) (interface{}, error) {
	parts := ParsePath(query)
	current := data

	for pi, part := range parts {
		if part.IsWildcard {
			arr, ok := current.([]interface{})
			if !ok {
				return nil, fmt.Errorf("cannot apply [*] to %s (expected array)", TypeName(current))
			}
			var results []interface{}
			remaining := BuildRemainingPath(parts, pi)
			for i, item := range arr {
				if remaining == "" {
					results = append(results, item)
				} else {
					val, err := Navigate(item, remaining)
					if err != nil {
						return nil, fmt.Errorf("[%d].%s: %v", i, remaining, err)
					}
					results = append(results, val)
				}
			}
			return results, nil
		}

		if part.IsIndex {
			arr, ok := current.([]interface{})
			if !ok {
				return nil, fmt.Errorf("cannot index %s with [%d] (expected array)", TypeName(current), part.ArrayIdx)
			}
			idx := part.ArrayIdx
			if idx < 0 {
				idx = len(arr) + idx // negative index from end
			}
			if idx < 0 || idx >= len(arr) {
				return nil, fmt.Errorf("array index %d out of range (length %d)", part.ArrayIdx, len(arr))
			}
			current = arr[idx]
			continue
		}

		// Object key access
		obj, ok := current.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("cannot access key %q on %s (expected object)", part.Key, TypeName(current))
		}
		val, exists := obj[part.Key]
		if !exists {
			return nil, fmt.Errorf("key %q not found", part.Key)
		}
		current = val
	}

	return current, nil
}

// ParsePath splits "items[0].name" into [{Key:"items"}, {IsIndex:true, ArrayIdx:0}, {Key:"name"}].
func ParsePath(query string) []PathPart {
	var parts []PathPart
	i := 0
	query = strings.TrimSpace(query)

	for i < len(query) {
		if query[i] == '.' {
			i++
			continue
		}

		if query[i] == '[' {
			end := strings.IndexByte(query[i:], ']')
			if end == -1 {
				parts = append(parts, PathPart{Key: query[i:]})
				break
			}
			inner := query[i+1 : i+end]
			if inner == "*" {
				parts = append(parts, PathPart{IsWildcard: true})
			} else {
				idx, err := strconv.Atoi(inner)
				if err != nil {
					parts = append(parts, PathPart{Key: inner})
				} else {
					parts = append(parts, PathPart{IsIndex: true, ArrayIdx: idx})
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
		parts = append(parts, PathPart{Key: query[i:end]})
		i = end
	}

	return parts
}

// BuildRemainingPath reconstructs the query path after a wildcard part.
func BuildRemainingPath(parts []PathPart, wildcardIdx int) string {
	remaining := parts[wildcardIdx+1:]
	if len(remaining) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, p := range remaining {
		if i > 0 && !p.IsIndex && !p.IsWildcard {
			sb.WriteByte('.')
		}
		if p.IsWildcard {
			sb.WriteString("[*]")
		} else if p.IsIndex {
			sb.WriteString(fmt.Sprintf("[%d]", p.ArrayIdx))
		} else {
			sb.WriteString(p.Key)
		}
	}
	return sb.String()
}

// TypeName returns a human-readable name for a value's type.
// Handles JSON (float64), TOML (int64, time.Time), and common Go types.
func TypeName(v interface{}) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case int64:
		return "number"
	case int:
		return "number"
	case string:
		return "string"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	case time.Time:
		return "datetime"
	default:
		return fmt.Sprintf("%T", v)
	}
}
