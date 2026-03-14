package proclist

import (
	"regexp"
	"strings"
)

// sensitiveArgFlags lists flags whose next argument should be masked.
// Note: "-p" is excluded due to frequent false positives (e.g. ssh -p 22).
var sensitiveArgFlags = map[string]bool{
	"--password":      true,
	"--passwd":        true,
	"--pass":          true,
	"--token":         true,
	"--secret":        true,
	"--key":           true,
	"--api-key":       true,
	"--apikey":        true,
	"--auth":          true,
	"--credential":    true,
	"--access-token":  true,
	"--client-secret": true,
}

// sensitiveEqualPrefixes lists flags that take values in "=" form.
var sensitiveEqualPrefixes = []string{
	"--password=",
	"--passwd=",
	"--pass=",
	"--token=",
	"--secret=",
	"--key=",
	"--api-key=",
	"--apikey=",
	"--auth=",
	"--credential=",
	"--access-token=",
	"--client-secret=",
}

// inlineEnvPattern matches sensitive environment variables in KEY=value form in command lines.
var inlineEnvPattern = regexp.MustCompile(`(?i)\b(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|CREDENTIAL|ACCESS_KEY|SIGNING_KEY)=(\S+)`)

// quotedArgPatterns match sensitive argument values enclosed in quotes.
// Go RE2 does not support backreferences, so separate patterns for double and single quotes.
var quotedArgPatternDQ = regexp.MustCompile(`(?i)(--(?:password|passwd|pass|token|secret|key|api-key|apikey|auth|credential|access-token|client-secret))\s+"[^"]*"`)
var quotedArgPatternSQ = regexp.MustCompile(`(?i)(--(?:password|passwd|pass|token|secret|key|api-key|apikey|auth|credential|access-token|client-secret))\s+'[^']*'`)

// urlCredentialPattern matches user:password@ patterns inside URLs.
var urlCredentialPattern = regexp.MustCompile(`://([^:@/]+):([^@]+)@`)

// bearerPattern matches Bearer/Basic tokens.
var bearerPattern = regexp.MustCompile(`(?i)(Bearer|Basic)\s+\S+`)

// SanitizeCommandLine masks sensitive arguments in a command line string.
func SanitizeCommandLine(cmdline string) string {
	if cmdline == "" {
		return cmdline
	}

	// Mask credentials in URLs: user:pass@ → user:***@
	result := urlCredentialPattern.ReplaceAllString(cmdline, "://$1:***@")

	// Mask Bearer/Basic tokens
	result = bearerPattern.ReplaceAllStringFunc(result, func(match string) string {
		parts := strings.SplitN(match, " ", 2)
		if len(parts) == 2 {
			return parts[0] + " ***"
		}
		return match
	})

	// Mask quoted sensitive arguments: --password "secret" → --password ***
	result = quotedArgPatternDQ.ReplaceAllString(result, "$1 ***")
	result = quotedArgPatternSQ.ReplaceAllString(result, "$1 ***")

	// Mask inline environment variables: PASSWORD=secret → PASSWORD=***
	result = inlineEnvPattern.ReplaceAllString(result, "${1}=***")

	// Mask --flag=value form
	for _, prefix := range sensitiveEqualPrefixes {
		lowerResult := strings.ToLower(result)
		idx := 0
		for {
			pos := strings.Index(lowerResult[idx:], strings.ToLower(prefix))
			if pos < 0 {
				break
			}
			absPos := idx + pos
			eqPos := absPos + len(prefix)
			// Find end of value (space or end of string)
			endPos := strings.IndexByte(result[eqPos:], ' ')
			if endPos < 0 {
				result = result[:eqPos] + "***"
				lowerResult = strings.ToLower(result)
			} else {
				result = result[:eqPos] + "***" + result[eqPos+endPos:]
				lowerResult = strings.ToLower(result)
			}
			idx = eqPos + 3
			if idx >= len(result) {
				break
			}
		}
	}

	// Mask the argument following -p, --password, etc.
	parts := strings.Fields(result)
	for i := 0; i < len(parts)-1; i++ {
		if sensitiveArgFlags[strings.ToLower(parts[i])] {
			parts[i+1] = "***"
		}
	}
	result = strings.Join(parts, " ")

	return result
}
