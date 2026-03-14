//go:build !windows

package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// getRules queries firewall rules on Linux using iptables or nft.
func getRules(filter string) (string, string, error) {
	// 1. Try iptables
	result, err := tryIptables(filter)
	if err == nil && strings.TrimSpace(result) != "" {
		return result, "iptables", nil
	}

	// 2. Try nftables
	result, err = tryNft(filter)
	if err == nil && strings.TrimSpace(result) != "" {
		return result, "nftables", nil
	}

	// 3. Try firewalld
	result, err = tryFirewalld(filter)
	if err == nil && strings.TrimSpace(result) != "" {
		return result, "firewalld", nil
	}

	return "", "", fmt.Errorf("no firewall tool available (tried: iptables, nft, firewall-cmd). Run with sudo if needed")
}

func tryIptables(filter string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "iptables", "-L", "-n", "--line-numbers")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	result := string(out)
	if filter != "" {
		result = filterLines(result, filter)
	}
	return result, nil
}

func tryNft(filter string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "list", "ruleset")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	result := string(out)
	if filter != "" {
		result = filterLines(result, filter)
	}
	return result, nil
}

func tryFirewalld(filter string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "firewall-cmd", "--list-all")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	result := string(out)
	if filter != "" {
		result = filterLines(result, filter)
	}
	return result, nil
}

// filterLines returns only lines containing the filter string from the output.
// Chain headers are also included to preserve context.
func filterLines(output, filter string) string {
	lines := strings.Split(output, "\n")
	filterLower := strings.ToLower(filter)
	var result []string
	lastChain := ""

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Chain ") {
			lastChain = line
			continue
		}
		if strings.Contains(strings.ToLower(line), filterLower) {
			if lastChain != "" {
				result = append(result, lastChain)
				lastChain = ""
			}
			result = append(result, line)
		}
	}

	if len(result) == 0 {
		return "No rules found matching: " + sanitizeFilterForOutput(filter)
	}
	return strings.Join(result, "\n")
}

// sanitizeFilterForOutput removes newlines and other control characters from the filter string.
func sanitizeFilterForOutput(filter string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, filter)
}
