//go:build windows

package firewall

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"agent-tool/common"
)

// getRules queries firewall rules on Windows using netsh.
func getRules(filter string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Always query all rules then filter manually (netsh name= parameter only supports exact matches)
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		return "", "", err
	}

	// Windows console output uses system code page — detect via GetACP() then convert to UTF-8
	// Remove \r (normalize Windows CRLF → LF)
	// NOTE: There is a known bug in Claude Code UI where non-ASCII UTF-8 in MCP tool results
	// is displayed as mojibake (anthropics/claude-code#34227). The actual JSON data is valid UTF-8.
	result := strings.ReplaceAll(common.DecodeConsoleOutput(out), "\r", "")

	// Apply filter
	if filter != "" {
		result = filterRuleBlocks(result, filter)
	} else {
		// Limit output size if no filter
		if len(result) > 30000 {
			result = result[:30000] + "\n\n... (output truncated, use filter to narrow results)"
		}
	}

	return result, "Windows Firewall (netsh)", nil
}

// filterRuleBlocks filters rules by block unit.
func filterRuleBlocks(output, filter string) string {
	blocks := splitRuleBlocks(output)
	filterLower := strings.ToLower(filter)

	var matched []string
	for _, block := range blocks {
		if strings.Contains(strings.ToLower(block), filterLower) {
			matched = append(matched, block)
		}
	}

	if len(matched) == 0 {
		return "No rules found matching: " + strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' {
				return ' '
			}
			return r
		}, filter)
	}
	result := strings.Join(matched, "\n"+strings.Repeat("-", 60)+"\n")
	if len(result) > 50000 {
		result = result[:50000] + "\n\n... (output truncated, use a more specific filter)"
	}
	return result
}

// splitRuleBlocks splits netsh output into rule blocks.
func splitRuleBlocks(output string) []string {
	lines := strings.Split(output, "\n")
	var blocks []string
	var current []string
	sep := strings.Repeat("-", 20) // netsh uses ---- separators

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Save current block at separator
		if strings.HasPrefix(trimmed, sep) {
			if len(current) > 0 {
				blocks = append(blocks, strings.Join(current, "\n"))
				current = nil
			}
			continue
		}
		if trimmed != "" {
			current = append(current, line)
		}
	}
	if len(current) > 0 {
		blocks = append(blocks, strings.Join(current, "\n"))
	}
	return blocks
}

