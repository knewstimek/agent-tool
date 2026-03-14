package proclist

import (
	"regexp"
	"strings"
)

// sensitiveArgFlags는 다음 인자를 마스킹해야 하는 플래그 목록이다.
// 주의: "-p"는 ssh -p 22 등 오탐이 많아 제외.
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

// sensitiveEqualPrefixes는 "=" 형태로 값이 오는 플래그이다.
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

// inlineEnvPattern은 커맨드라인의 KEY=value 형태 민감 환경변수를 매칭한다.
var inlineEnvPattern = regexp.MustCompile(`(?i)\b(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|CREDENTIAL|ACCESS_KEY|SIGNING_KEY)=(\S+)`)

// quotedArgPatterns는 따옴표로 감싼 민감 인자값을 매칭한다.
// Go RE2는 백레퍼런스 미지원이므로 큰따옴표/작은따옴표 각각 패턴 정의.
var quotedArgPatternDQ = regexp.MustCompile(`(?i)(--(?:password|passwd|pass|token|secret|key|api-key|apikey|auth|credential|access-token|client-secret))\s+"[^"]*"`)
var quotedArgPatternSQ = regexp.MustCompile(`(?i)(--(?:password|passwd|pass|token|secret|key|api-key|apikey|auth|credential|access-token|client-secret))\s+'[^']*'`)

// urlCredentialPattern은 URL 안의 user:password@ 패턴을 매칭한다.
var urlCredentialPattern = regexp.MustCompile(`://([^:@/]+):([^@]+)@`)

// bearerPattern은 Bearer/Basic 토큰을 매칭한다.
var bearerPattern = regexp.MustCompile(`(?i)(Bearer|Basic)\s+\S+`)

// SanitizeCommandLine은 커맨드라인에서 민감한 인자를 마스킹한다.
func SanitizeCommandLine(cmdline string) string {
	if cmdline == "" {
		return cmdline
	}

	// URL 안의 credential 마스킹: user:pass@ → user:***@
	result := urlCredentialPattern.ReplaceAllString(cmdline, "://$1:***@")

	// Bearer/Basic 토큰 마스킹
	result = bearerPattern.ReplaceAllStringFunc(result, func(match string) string {
		parts := strings.SplitN(match, " ", 2)
		if len(parts) == 2 {
			return parts[0] + " ***"
		}
		return match
	})

	// 따옴표로 감싼 민감 인자 마스킹: --password "secret" → --password ***
	result = quotedArgPatternDQ.ReplaceAllString(result, "$1 ***")
	result = quotedArgPatternSQ.ReplaceAllString(result, "$1 ***")

	// 인라인 환경변수 마스킹: PASSWORD=secret → PASSWORD=***
	result = inlineEnvPattern.ReplaceAllString(result, "${1}=***")

	// --flag=value 형태 마스킹
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
			// 값의 끝 찾기 (공백 또는 문자열 끝)
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

	// -p, --password 다음 인자 마스킹
	parts := strings.Fields(result)
	for i := 0; i < len(parts)-1; i++ {
		if sensitiveArgFlags[strings.ToLower(parts[i])] {
			parts[i+1] = "***"
		}
	}
	result = strings.Join(parts, " ")

	return result
}
