package common

import (
	"fmt"
	"regexp"
	"strings"
)

// DLP (Data Loss Prevention) — scans outbound data for high-confidence
// sensitive patterns before transmission. Only patterns with near-zero
// false positive rates are included. This blocks the most direct
// exfiltration path (HTTP POST body) from prompt injection attacks.

// SensitiveMatch describes a detected sensitive pattern in outbound data.
type SensitiveMatch struct {
	PatternName string // Human-readable name (e.g., "PEM Private Key")
	Matched     string // The matched substring (truncated for display)
}

// sensitivePattern defines a high-confidence pattern that should never
// appear in outbound HTTP request bodies from an AI coding agent.
type sensitivePattern struct {
	name    string
	re      *regexp.Regexp
	extract func(match string) string // optional: extract display-safe portion
}

var sensitivePatterns []sensitivePattern

func init() {
	sensitivePatterns = []sensitivePattern{
		{
			// PEM private keys — RSA, EC, OPENSSH, DSA, PKCS8, PGP, etc.
			// No legitimate reason for an AI agent to POST private keys.
			name: "PEM Private Key",
			re:   regexp.MustCompile(`-----BEGIN\s[\w\s]*PRIVATE KEY-----`),
		},
		{
			// AWS Access Key IDs — exactly AKIA + 16 uppercase alphanumeric.
			// Other prefixes: ASIA (temporary), ABIA, ACCA, etc.
			name: "AWS Access Key",
			re:   regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[0-9A-Z]{16}`),
		},
		{
			// GCP service account key file — contains private_key_id field
			// which is unique to service account JSON credentials.
			name: "GCP Service Account Key",
			re:   regexp.MustCompile(`"private_key_id"\s*:\s*"[a-f0-9]{40}"`),
		},
		{
			// GitHub Personal Access Tokens (classic: ghp_, fine-grained: github_pat_)
			// and GitHub App tokens (ghs_, ghr_)
			name: "GitHub Token",
			re:   regexp.MustCompile(`(?:ghp|ghs|ghr|gho|github_pat)_[A-Za-z0-9_]{36,255}`),
		},
		{
			// GitLab Personal/Project/Group Access Tokens
			name: "GitLab Token",
			re:   regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20,}`),
		},
		{
			// Slack Bot/User/Webhook tokens
			name: "Slack Token",
			re:   regexp.MustCompile(`xox[bporas]-[0-9]{10,}-[A-Za-z0-9\-]{20,}`),
		},
		{
			// .env file dump — 3+ consecutive KEY=VALUE lines with
			// secret-indicating names. Single KEY=VALUE is normal in configs,
			// but consecutive ones with SECRET/KEY/TOKEN/PASSWORD suggest a
			// full .env dump being exfiltrated.
			// Use \r?\n to handle both Unix and Windows line endings.
			name: ".env File Dump",
			re:   regexp.MustCompile(`(?m)(?:^[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*=\S+(?:\r?\n)?){3,}`),
		},
	}
}

// ScanSensitiveData checks if the given data contains high-confidence
// sensitive patterns. Returns nil if no sensitive data is detected.
// Only call this for outbound data (POST/PUT/PATCH bodies).
func ScanSensitiveData(data string) []SensitiveMatch {
	if len(data) == 0 {
		return nil
	}

	var matches []SensitiveMatch
	for _, p := range sensitivePatterns {
		loc := p.re.FindString(data)
		if loc == "" {
			continue
		}
		// Truncate matched string for safe display (don't echo full secrets)
		display := loc
		if len(display) > 40 {
			display = display[:40] + "..."
		}
		matches = append(matches, SensitiveMatch{
			PatternName: p.name,
			Matched:     display,
		})
	}
	return matches
}

// FormatDLPBlock formats a DLP block message for tool output.
// This message is returned as an error to prevent the request from being sent.
func FormatDLPBlock(matches []SensitiveMatch) string {
	var sb strings.Builder
	sb.WriteString("🚫 BLOCKED: Request body contains sensitive data that should not be transmitted.\n")
	sb.WriteString("Detected patterns:\n")
	for _, m := range matches {
		sb.WriteString(fmt.Sprintf("  - %s: %s\n", m.PatternName, m.Matched))
	}
	sb.WriteString("\nThis may be a prompt injection attack attempting to exfiltrate secrets.\n")
	sb.WriteString("If you intentionally need to send this data, review the request carefully.")
	return sb.String()
}
