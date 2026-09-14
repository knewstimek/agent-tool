package toolbox

import (
	"context"
	"strings"
	"testing"

	"agent-tool/common"
	"agent-tool/tools/analyze"
	copytool "agent-tool/tools/copy"
	mysqltool "agent-tool/tools/mysql"
	"agent-tool/tools/sftp"
	"agent-tool/tools/ssh"
	"agent-tool/tools/sshkey"
	"agent-tool/tools/wintool"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestProfilesStayCompactAndComposable(t *testing.T) {
	names, groups, ok := profileSelection("core-lite")
	if !ok || len(groups) != 0 || strings.Join(names, ",") != "edit,grep,read,write" {
		t.Fatalf("core-lite profile = names:%v groups:%v ok:%v", names, groups, ok)
	}
	if groups, ok := profileGroups("core"); !ok || len(groups) != 1 || groups[0] != "core" {
		t.Fatalf("core profile = %v, %v", groups, ok)
	}
	if groups, ok := profileGroups("remote"); !ok || len(groups) != 2 {
		t.Fatalf("remote profile = %v, %v", groups, ok)
	}
	if _, ok := profileGroups("everything-ish"); ok {
		t.Fatal("unknown profile was accepted")
	}
}

func TestCoreLiteEnablesOnlyFrequentTools(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	registered := map[string]int{}
	specs := []Spec{
		{Name: "edit", Group: "core", Register: func() { registered["edit"]++ }},
		{Name: "grep", Group: "core", Register: func() { registered["grep"]++ }},
		{Name: "read", Group: "core", Register: func() { registered["read"]++ }},
		{Name: "write", Group: "core", Register: func() { registered["write"]++ }},
		{Name: "glob", Group: "core", Register: func() { registered["glob"]++ }},
	}
	m := NewManager(server, specs)
	if err := m.EnableProfile("core-lite"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"edit", "grep", "read", "write"} {
		if registered[name] != 1 {
			t.Fatalf("%s registration count = %d", name, registered[name])
		}
	}
	if registered["glob"] != 0 {
		t.Fatalf("core-lite unexpectedly registered glob: %#v", registered)
	}
}

func TestCompactDescribeFiltersByTargetOperationAndReusesHandle(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "v1"}, nil)
	m := NewManager(server, []Spec{
		{Name: "analyze", Group: "analysis", Register: func() { analyze.Register(server) }},
		{Name: "ssh", Group: "remote", Register: func() { ssh.Register(server) }},
		{Name: "sftp", Group: "remote", Register: func() { sftp.Register(server) }},
		{Name: "ssh_key", Group: "remote", Register: func() { sshkey.Register(server) }},
	}, "v1")

	result, out, err := m.Handle(context.Background(), nil, Input{
		Operation: "describe", Tool: "ssh", Compact: true, ToolOperation: "execute",
	})
	if err != nil || result.IsError {
		t.Fatalf("compact describe failed: result=%v err=%v", result, err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	for _, want := range []string{`"command"`, `"quiet"`, `"echo_command"`, `"required":["command"]`} {
		if !strings.Contains(text, want) {
			t.Fatalf("compact schema omitted %s: %s", want, text)
		}
	}
	for _, unwanted := range []string{`"job_id"`, "Description:\n"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("compact schema retained %s: %s", unwanted, text)
		}
	}
	if out.SchemaHandle == "" {
		t.Fatal("compact describe did not return a schema handle")
	}
	full, _, err := m.Handle(context.Background(), nil, Input{Operation: "describe", Tool: "ssh"})
	if err != nil || full.IsError {
		t.Fatalf("full describe failed: result=%v err=%v", full, err)
	}
	fullText := full.Content[0].(*mcp.TextContent).Text
	if len(text) >= len(fullText) {
		t.Fatalf("compact describe was not smaller: compact=%d full=%d", len(text), len(fullText))
	}

	cached, cachedOut, err := m.Handle(context.Background(), nil, Input{
		Operation: "describe", Tool: "ssh", Compact: true, ToolOperation: "execute", SchemaHandle: out.SchemaHandle,
	})
	if err != nil || cached.IsError || cachedOut.SchemaHandle != out.SchemaHandle {
		t.Fatalf("schema handle reuse failed: result=%v out=%v err=%v", cached, cachedOut, err)
	}
	cachedText := cached.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(cachedText, "Schema unchanged") || strings.Contains(cachedText, `"properties"`) {
		t.Fatalf("unexpected cached response: %s", cachedText)
	}

	upload, _, err := m.Handle(context.Background(), nil, Input{
		Operation: "describe", Tool: "sftp", Compact: true, ToolOperation: "upload",
	})
	if err != nil || upload.IsError {
		t.Fatalf("upload describe failed: result=%v err=%v", upload, err)
	}
	uploadText := upload.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(uploadText, `"local_path"`) || !strings.Contains(uploadText, `"remote_path"`) || strings.Contains(uploadText, `"transfer_id"`) {
		t.Fatalf("unexpected upload schema: %s", uploadText)
	}

	keyConvert, _, err := m.Handle(context.Background(), nil, Input{
		Operation: "describe", Tool: "ssh_key", Compact: true, ToolOperation: "convert",
	})
	if err != nil || keyConvert.IsError {
		t.Fatalf("ssh_key describe failed: result=%v err=%v", keyConvert, err)
	}
	keyText := keyConvert.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(keyText, `"input_path"`) || !strings.Contains(keyText, `"output_format"`) || strings.Contains(keyText, `"connection_id"`) || strings.Contains(keyText, `"anyOf"`) {
		t.Fatalf("unexpected ssh_key schema: %s", keyText)
	}

	instructionSearch, _, err := m.Handle(context.Background(), nil, Input{
		Operation: "describe", Tool: "analyze", Compact: true, ToolOperation: "instruction_search",
	})
	if err != nil || instructionSearch.IsError {
		t.Fatalf("instruction_search describe failed: result=%v err=%v", instructionSearch, err)
	}
	instructionText := instructionSearch.Content[0].(*mcp.TextContent).Text
	for _, want := range []string{`"operation"`, `"file_path"`, `"mnemonic"`, `"register"`, `"immediate"`, `"call_target"`, `"findings"`, `"trace_values"`, `"required":["operation","file_path"]`} {
		if !strings.Contains(instructionText, want) {
			t.Fatalf("instruction_search compact schema omitted %s: %s", want, instructionText)
		}
	}
	for _, unwanted := range []string{`"target_va"`, `"pattern"`, `"file_path_b"`} {
		if strings.Contains(instructionText, unwanted) {
			t.Fatalf("instruction_search compact schema retained %s: %s", unwanted, instructionText)
		}
	}
}

func TestCompactDescribeSupportsFrequentDeferredOperations(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "v1"}, nil)
	m := NewManager(server, []Spec{
		{Name: "analyze", Group: "analysis", Register: func() { analyze.Register(server) }},
		{Name: "copy", Group: "file", Register: func() { copytool.Register(server) }},
		{Name: "mysql", Group: "data", Register: func() { mysqltool.Register(server) }},
		{Name: "wintool", Group: "windows", Register: func() { wintool.Register(server) }},
	}, "v1")

	tests := []struct {
		tool      string
		operation string
		want      []string
		unwanted  []string
	}{
		{tool: "copy", operation: "copy", want: []string{`"source"`, `"destination"`, `"overwrite"`, `"required":["source","destination"]`}, unwanted: []string{`"src"`, `"dst"`}},
		{tool: "mysql", operation: "query", want: []string{`"host"`, `"user"`, `"query"`, `"max_rows"`, `"required":["host","user","query"]`}},
		{tool: "analyze", operation: "disassemble", want: []string{`"operation"`, `"const":"disassemble"`, `Fixed operation: disassemble`, `"file_path"`, `"va"`, `"stop_at_ret"`}, unwanted: []string{`"pattern"`, `"file_path_b"`, `"target_va"`}},
		{tool: "wintool", operation: "screenshot", want: []string{`"operation"`, `"const":"screenshot"`, `Fixed operation: screenshot`, `"hwnd"`, `"save_path"`}, unwanted: []string{`"text"`, `"msg"`, `"move_x"`}},
		{tool: "wintool", operation: "clipboard", want: []string{`"operation"`, `"const":"clipboard"`, `Fixed operation: clipboard`, `"save_path"`, `"required":["operation"]`}, unwanted: []string{`"hwnd"`, `"text"`, `"msg"`}},
	}

	for _, tt := range tests {
		t.Run(tt.tool+"/"+tt.operation, func(t *testing.T) {
			result, _, err := m.Handle(context.Background(), nil, Input{
				Operation: "describe", Tool: tt.tool, Compact: true, ToolOperation: tt.operation,
			})
			if err != nil || result.IsError {
				t.Fatalf("compact describe failed: result=%v err=%v", result, err)
			}
			text := result.Content[0].(*mcp.TextContent).Text
			for _, want := range tt.want {
				if !strings.Contains(text, want) {
					t.Fatalf("schema omitted %s: %s", want, text)
				}
			}
			for _, unwanted := range tt.unwanted {
				if strings.Contains(text, unwanted) {
					t.Fatalf("schema retained %s: %s", unwanted, text)
				}
			}
		})
	}
}

func TestEveryCompactShapeReferencesRegisteredFields(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "v1"}, nil)
	m := NewManager(server, []Spec{
		{Name: "analyze", Group: "analysis", Register: func() { analyze.Register(server) }},
		{Name: "copy", Group: "file", Register: func() { copytool.Register(server) }},
		{Name: "mysql", Group: "data", Register: func() { mysqltool.Register(server) }},
		{Name: "sftp", Group: "remote", Register: func() { sftp.Register(server) }},
		{Name: "ssh", Group: "remote", Register: func() { ssh.Register(server) }},
		{Name: "ssh_key", Group: "remote", Register: func() { sshkey.Register(server) }},
		{Name: "wintool", Group: "windows", Register: func() { wintool.Register(server) }},
	}, "v1")

	for tool, operations := range compactOperationShapes {
		for operation := range operations {
			t.Run(tool+"/"+operation, func(t *testing.T) {
				result, _, err := m.Handle(context.Background(), nil, Input{
					Operation: "describe", Tool: tool, Compact: true, ToolOperation: operation,
				})
				if err != nil || result.IsError {
					t.Fatalf("invalid compact shape: result=%v err=%v", result, err)
				}
			})
		}
	}
}

func TestManagerEnablesOnlyRequestedGroup(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	registered := map[string]int{}
	m := NewManager(server, []Spec{
		{Name: "read", Group: "core", Register: func() { registered["read"]++ }},
		{Name: "ssh", Group: "remote", Register: func() { registered["ssh"]++ }},
	})
	if err := m.EnableProfile("core"); err != nil {
		t.Fatal(err)
	}
	if registered["read"] != 1 || registered["ssh"] != 0 {
		t.Fatalf("registered = %#v", registered)
	}
	if err := m.EnableProfile("core"); err != nil || registered["read"] != 1 {
		t.Fatalf("duplicate enable = %#v, %v", registered, err)
	}
}

func TestInventoryShowsConciseDiscoveryHint(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	m := NewManager(server, []Spec{{
		Name: "analyze", Group: "analysis", Hint: "binary disassembly and assembly/value search", Register: func() {},
	}})
	result, _, err := m.Handle(context.Background(), nil, Input{})
	if err != nil || result.IsError {
		t.Fatalf("inventory failed: result=%v err=%v", result, err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "analyze (binary disassembly and assembly/value search)") {
		t.Fatalf("inventory omitted discovery hint: %s", text)
	}
}

type gatewayEchoInput struct {
	Message string `json:"message" jsonschema:"Message to echo,required"`
}

type gatewayEchoOutput struct {
	Message string `json:"message"`
}

func TestGatewayDescribesAndCallsToolWithoutClientRefresh(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	m := NewManager(server, []Spec{{
		Name: "echo", Group: "remote", Register: func() {
			common.SafeAddTool(server, &mcp.Tool{Name: "echo", Description: "Echo a message."},
				func(_ context.Context, _ *mcp.CallToolRequest, input gatewayEchoInput) (*mcp.CallToolResult, gatewayEchoOutput, error) {
					text := "echo: " + input.Message
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, gatewayEchoOutput{Message: text}, nil
				})
		},
	}})

	describeResult, _, err := m.Handle(context.Background(), nil, Input{Operation: "describe", Tool: "echo"})
	if err != nil || describeResult.IsError {
		t.Fatalf("describe failed: result=%v err=%v", describeResult, err)
	}
	description := describeResult.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(description, `"message"`) || !strings.Contains(description, "operation=call") {
		t.Fatalf("describe omitted schema or gateway guidance: %s", description)
	}

	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "toolbox"}}
	callResult, _, err := m.Handle(context.Background(), req, Input{
		Operation: "call", Tool: "echo", Arguments: map[string]any{"message": "hello"},
	})
	if err != nil || callResult.IsError {
		t.Fatalf("gateway call failed: result=%v err=%v", callResult, err)
	}
	if got := callResult.Content[0].(*mcp.TextContent).Text; got != "echo: hello" {
		t.Fatalf("gateway result = %q", got)
	}
}

func TestGatewayPreservesTargetValidationErrors(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	m := NewManager(server, []Spec{{
		Name: "echo", Group: "remote", Register: func() {
			common.SafeAddTool(server, &mcp.Tool{Name: "echo"},
				func(_ context.Context, _ *mcp.CallToolRequest, input gatewayEchoInput) (*mcp.CallToolResult, gatewayEchoOutput, error) {
					return nil, gatewayEchoOutput{}, nil
				})
		},
	}})
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "toolbox"}}
	result, _, err := m.Handle(context.Background(), req, Input{Operation: "call", Tool: "echo"})
	if err != nil || !result.IsError {
		t.Fatalf("expected target validation tool error: result=%v err=%v", result, err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "validation error") || !strings.Contains(text, "message") {
		t.Fatalf("unexpected validation result: %s", text)
	}
}

func TestToolboxOutputRetrievesPreservedRawCommandOutput(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	m := NewManager(server, nil)
	id := common.PreserveRawOutput("bash", "warning: original\nwarning: original\n", false, 36)
	if id == "" {
		t.Fatal("failed to preserve test output")
	}
	result, _, err := m.Handle(context.Background(), nil, Input{Operation: "output", OutputID: id})
	if err != nil || result.IsError {
		t.Fatalf("output lookup failed: result=%v err=%v", result, err)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	for _, want := range []string{"source: bash", "warning: original\nwarning: original\n"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
	paged, _, err := m.Handle(context.Background(), nil, Input{
		Operation: "output", OutputID: id, OutputMaxChars: 10,
	})
	if err != nil || paged.IsError {
		t.Fatalf("paged output lookup failed: result=%v err=%v", paged, err)
	}
	pagedText := paged.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(pagedText, "next_offset: 10") || !strings.HasSuffix(pagedText, "warning: o") {
		t.Fatalf("unexpected paged output: %q", pagedText)
	}
}
