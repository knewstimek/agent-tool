package toolbox

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type operationShape struct {
	fields             []string
	required           []string
	requiresConnection bool
}

var connectionFields = []string{
	"connection_profile", "connection_id", "host", "port", "user", "password",
	"key_file", "passphrase", "use_agent", "host_key_check", "jump_host",
	"jump_port", "jump_user", "jump_password", "jump_key_file", "jump_passphrase",
}

func fileOnlyAnalyzeShape() operationShape {
	return operationShape{
		fields:   []string{"operation", "file_path"},
		required: []string{"operation", "file_path"},
	}
}

var compactOperationShapes = map[string]map[string]operationShape{
	"analyze": {
		"disassemble": {
			fields:   []string{"operation", "file_path", "offset", "va", "count", "stop_at_ret", "mode", "base_addr", "arch"},
			required: []string{"operation", "file_path"},
		},
		"instruction_search": {
			fields:   []string{"operation", "file_path", "mnemonic", "register", "immediate", "call_target", "findings", "trace_values", "max_results"},
			required: []string{"operation", "file_path"},
		},
		"pe_info": {
			fields:   []string{"operation", "file_path", "section", "rva", "result_offset", "max_results", "max_output_chars"},
			required: []string{"operation", "file_path"},
		},
		"elf_info":       {fields: []string{"operation", "file_path", "section"}, required: []string{"operation", "file_path"}},
		"macho_info":     {fields: []string{"operation", "file_path", "section"}, required: []string{"operation", "file_path"}},
		"strings":        {fields: []string{"operation", "file_path", "min_length", "max_results", "encoding"}, required: []string{"operation", "file_path"}},
		"hexdump":        {fields: []string{"operation", "file_path", "offset", "va", "length"}, required: []string{"operation", "file_path"}},
		"pattern_search": {fields: []string{"operation", "file_path", "pattern", "max_results"}, required: []string{"operation", "file_path", "pattern"}},
		"entropy":        fileOnlyAnalyzeShape(),
		"resource_info":  fileOnlyAnalyzeShape(),
		"imphash":        fileOnlyAnalyzeShape(),
		"rich_header":    fileOnlyAnalyzeShape(),
		"overlay_detect": fileOnlyAnalyzeShape(),
		"dwarf_info":     fileOnlyAnalyzeShape(),
		"vtable_scan":    fileOnlyAnalyzeShape(),
		"bin_diff":       {fields: []string{"operation", "file_path", "file_path_b", "max_results"}, required: []string{"operation", "file_path", "file_path_b"}},
		"xref":           {fields: []string{"operation", "file_path", "target_va", "target_end_va", "max_results"}, required: []string{"operation", "file_path", "target_va"}},
		"function_at":    {fields: []string{"operation", "file_path", "va", "count"}, required: []string{"operation", "file_path", "va"}},
		"call_graph":     {fields: []string{"operation", "file_path", "va", "count", "max_results"}, required: []string{"operation", "file_path", "va"}},
		"follow_ptr":     {fields: []string{"operation", "file_path", "va", "count"}, required: []string{"operation", "file_path", "va"}},
		"rtti_dump":      {fields: []string{"operation", "file_path", "va"}, required: []string{"operation", "file_path", "va"}},
		"struct_layout":  {fields: []string{"operation", "file_path", "va", "length"}, required: []string{"operation", "file_path", "va"}},
	},
	"copy": {
		"copy": {
			fields:   []string{"source", "destination", "overwrite", "dry_run"},
			required: []string{"source", "destination"},
		},
	},
	"mysql": {
		"query": {
			fields:   []string{"host", "port", "user", "password", "database", "query", "timeout_sec", "tls", "max_rows", "max_columns", "max_value_chars", "max_output_chars"},
			required: []string{"host", "user", "query"},
		},
	},
	"ssh": {
		"execute": {
			fields:             append(append([]string{}, connectionFields...), "operation", "command", "timeout_sec", "max_output_chars", "output_mode", "quiet", "echo_command", "result_only"),
			required:           []string{"command"},
			requiresConnection: true,
		},
	},
	"ssh_key": {
		"convert": {
			fields:   []string{"operation", "input_path", "output_path", "output_format", "input_passphrase", "output_passphrase", "comment", "overwrite"},
			required: []string{"input_path", "output_path", "output_format"},
		},
	},
	"sftp": {
		"upload": {
			fields:             append(append([]string{}, connectionFields...), "operation", "local_path", "remote_path", "overwrite", "quiet", "result_only"),
			required:           []string{"operation", "local_path", "remote_path"},
			requiresConnection: true,
		},
		"upload_many": {
			fields:             append(append([]string{}, connectionFields...), "operation", "uploads", "overwrite", "quiet", "result_only"),
			required:           []string{"operation", "uploads"},
			requiresConnection: true,
		},
	},
	"wintool": {
		"screenshot": {fields: []string{"operation", "hwnd", "save_path"}, required: []string{"operation", "hwnd"}},
		"clipboard":  {fields: []string{"operation", "save_path"}, required: []string{"operation"}},
	},
}

func compactInputSchema(encoded []byte, tool, operation string) ([]byte, error) {
	var schema map[string]any
	if err := json.Unmarshal(encoded, &schema); err != nil {
		return nil, err
	}
	properties, _ := schema["properties"].(map[string]any)
	if properties == nil {
		return nil, fmt.Errorf("schema has no object properties")
	}

	operation = strings.ToLower(strings.TrimSpace(operation))
	shape, hasShape := compactOperationShapes[tool][operation]
	if operation != "" && !hasShape {
		available := make([]string, 0, len(compactOperationShapes[tool]))
		for name := range compactOperationShapes[tool] {
			available = append(available, name)
		}
		sort.Strings(available)
		if len(available) == 0 {
			return nil, fmt.Errorf("tool %q has no operation-specific compact schema", tool)
		}
		return nil, fmt.Errorf("compact schema for %s operation %q is unavailable (available: %s)", tool, operation, strings.Join(available, ", "))
	}

	result := map[string]any{"type": "object"}
	filtered := make(map[string]any)
	if hasShape {
		for _, name := range shape.fields {
			property, ok := properties[name]
			if !ok {
				return nil, fmt.Errorf("compact schema for %s/%s references unknown field %q", tool, operation, name)
			}
			filtered[name] = property
		}
		if operationProperty, ok := filtered["operation"].(map[string]any); ok {
			copyProperty := make(map[string]any, len(operationProperty)+1)
			for key, value := range operationProperty {
				copyProperty[key] = value
			}
			copyProperty["const"] = operation
			copyProperty["description"] = "Fixed operation: " + operation
			filtered["operation"] = copyProperty
		}
		if len(shape.required) > 0 {
			for _, name := range shape.required {
				if _, ok := filtered[name]; !ok {
					return nil, fmt.Errorf("compact schema for %s/%s requires omitted field %q", tool, operation, name)
				}
			}
			result["required"] = shape.required
		}
		if shape.requiresConnection {
			result["anyOf"] = []any{
				map[string]any{"required": []string{"connection_id"}},
				map[string]any{"required": []string{"connection_profile"}},
				map[string]any{"required": []string{"host", "user"}},
			}
		}
	} else {
		// Generic compact mode keeps all fields but strips verbose root metadata.
		for name, property := range properties {
			filtered[name] = property
		}
		if required, ok := schema["required"]; ok {
			result["required"] = required
		}
	}
	result["properties"] = filtered
	return json.Marshal(result)
}
