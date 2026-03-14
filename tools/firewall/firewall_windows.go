//go:build windows

package firewall

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"agent-tool/common"
)

// getRules는 Windows에서 netsh로 방화벽 규칙을 조회한다.
func getRules(filter string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 항상 name=all로 전체 조회 후 직접 필터링 (netsh의 name= 파라미터는 정확한 이름만 지원)
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		return "", "", err
	}

	// Windows 콘솔 출력은 시스템 코드페이지 — GetACP()로 감지 후 UTF-8 변환
	// \r 제거 (Windows CRLF → LF 정규화)
	// NOTE: Claude Code UI에서 MCP tool result의 non-ASCII UTF-8이 mojibake로 표시되는
	// 알려진 버그가 있음 (anthropics/claude-code#34227). 실제 JSON 데이터는 정상 UTF-8.
	result := strings.ReplaceAll(common.DecodeConsoleOutput(out), "\r", "")

	// 필터 적용
	if filter != "" {
		result = filterRuleBlocks(result, filter)
	} else {
		// 필터 없으면 출력 크기 제한
		if len(result) > 30000 {
			result = result[:30000] + "\n\n... (output truncated, use filter to narrow results)"
		}
	}

	return result, "Windows Firewall (netsh)", nil
}

// filterRuleBlocks는 규칙 블록 단위로 필터링한다.
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

// splitRuleBlocks는 netsh 출력을 규칙 블록으로 분리한다.
func splitRuleBlocks(output string) []string {
	lines := strings.Split(output, "\n")
	var blocks []string
	var current []string
	sep := strings.Repeat("-", 20) // netsh는 ---- 구분선 사용

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// 구분선이면 현재 블록 저장
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

