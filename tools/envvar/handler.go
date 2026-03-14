package envvar

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type EnvVarInput struct {
	Name   string `json:"name,omitempty" jsonschema:"Get a specific environment variable by exact name"`
	Filter string `json:"filter,omitempty" jsonschema:"Filter variables by name (case-insensitive partial match)"`
}

type EnvVarOutput struct {
	Result string `json:"result"`
}

// sensitiveKeywords는 값을 마스킹할 변수 이름 키워드이다.
// AUTH는 범위가 넓어 AUTHOR 등을 오탐하므로 구체적 패턴만 사용.
var sensitiveKeywords = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN", "CREDENTIAL",
	"API_KEY", "APIKEY", "PRIVATE", "ACCESS_KEY", "SIGNING_KEY",
	"AUTH_TOKEN", "AUTH_KEY", "AUTH_SECRET",
}

// safeSuffixes는 키워드가 포함되어도 마스킹하지 않을 접미사이다.
var safeSuffixes = []string{
	"_PATH", "_FILE", "_DIR", "_HOME", "_ROOT", "_URL", "_URI",
	"_STORE", "_PROVIDER", "_TYPE", "_MODE", "_LEVEL",
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input EnvVarInput) (*mcp.CallToolResult, EnvVarOutput, error) {
	// 특정 변수 조회
	if input.Name != "" {
		// 개행 제거 (출력 인젝션 방지)
		name := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, strings.TrimSpace(input.Name))
		val, ok := os.LookupEnv(name)
		if !ok {
			return errorResult(fmt.Sprintf("environment variable not found: %s", name))
		}
		if isSensitive(name) {
			val = maskValue(val)
		}
		msg := fmt.Sprintf("%s=%s", name, val)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, EnvVarOutput{Result: msg}, nil
	}

	// 전체 또는 필터된 목록
	envs := os.Environ()
	filter := strings.ToUpper(strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, input.Filter)))

	var items []string
	for _, env := range envs {
		eqIdx := strings.IndexByte(env, '=')
		if eqIdx < 0 {
			continue
		}
		name := env[:eqIdx]
		value := env[eqIdx+1:]

		if filter != "" && !strings.Contains(strings.ToUpper(name), filter) {
			continue
		}

		if isSensitive(name) {
			value = maskValue(value)
		}

		// 긴 값 자르기 (PATH 등)
		if len(value) > 500 {
			value = value[:497] + "..."
		}

		items = append(items, fmt.Sprintf("%s=%s", name, value))
	}

	sort.Strings(items)

	var sb strings.Builder
	sb.WriteString("=== Environment Variables ===\n\n")
	for _, item := range items {
		sb.WriteString(item + "\n")
	}
	sb.WriteString(fmt.Sprintf("\nTotal: %d variables shown", len(items)))
	if filter != "" {
		sb.WriteString(fmt.Sprintf(" (filtered from %d)", len(envs)))
	}
	sb.WriteString("\n")

	result := sb.String()
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, EnvVarOutput{Result: result}, nil
}

func Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "envvar",
		Description: `Reads environment variables. Returns a single variable by name, or lists all with optional filter.
Sensitive values (passwords, tokens, keys) are automatically masked for security.`,
	}, Handle)
}

// isSensitive는 변수 이름이 민감한 키워드를 포함하는지 확인한다.
func isSensitive(name string) bool {
	upper := strings.ToUpper(name)

	// 안전한 접미사면 마스킹 제외
	for _, suffix := range safeSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return false
		}
	}

	// 먼저 키워드 매칭 확인
	matched := false
	for _, kw := range sensitiveKeywords {
		if strings.Contains(upper, kw) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}

	// PUBLIC이 포함되어도 SECRET/TOKEN 등도 함께 포함되면 민감으로 판단
	// 예: PUBLIC_SECRET_KEY → 민감, PUBLIC_KEY → 비민감
	if strings.Contains(upper, "PUBLIC") {
		// SECRET, TOKEN, PASSWORD 등 강한 키워드가 같이 있으면 민감
		strongKeywords := []string{"SECRET", "PASSWORD", "PASSWD", "TOKEN", "CREDENTIAL", "PRIVATE"}
		for _, sk := range strongKeywords {
			if strings.Contains(upper, sk) {
				return true
			}
		}
		return false
	}

	return true
}

// maskValue는 값을 부분 마스킹한다.
// 짧은 값(8자 이하)은 전부 마스킹, 그 외는 앞 4자만 노출.
func maskValue(val string) string {
	if len(val) <= 8 {
		return "***"
	}
	return val[:4] + "***"
}

func errorResult(msg string) (*mcp.CallToolResult, EnvVarOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, EnvVarOutput{Result: msg}, nil
}
