package bash

import "strings"

// chainSegment represents a command part between && / || operators.
type chainSegment struct {
	Text string // the command text (trimmed)
	Op   string // operator AFTER this segment: "&&", "||", or "" for last
}

// chainParse holds the result of parsing chain operators from a command.
type chainParse struct {
	Segments     []chainSegment
	HasNestedOps bool // && / || found inside $() or () — PS 5.1 can't handle these
}

// HasChainOps returns true if top-level && or || operators were found outside quotes.
func (p chainParse) HasChainOps() bool {
	return len(p.Segments) > 1
}

// NeedsDelegation returns true if the command contains && / || inside nested
// structures like $() or () that PowerShell 5.1 cannot parse.
func (p chainParse) NeedsDelegation() bool {
	return p.HasNestedOps
}

// HasEmptySegment returns true if any segment is empty (e.g. "&& cmd" or "cmd &&").
func (p chainParse) HasEmptySegment() bool {
	for _, s := range p.Segments {
		if s.Text == "" {
			return true
		}
	}
	return false
}

// parseChainOps tokenizes a bash command, splitting by top-level && and ||
// operators while correctly handling:
//   - Single quotes: content is literal, no escaping (bash rule)
//   - Double quotes: backslash escapes \" and \\ (bash rule)
//   - $() command substitution and () subshells: tracked via paren depth,
//     so && / || inside these are NOT treated as top-level operators
//
// This is the single source of truth for quote-aware chain operator parsing.
// All consumers (hasChainOps, buildPSChainOps, handler warnings) should use
// this function instead of ad-hoc string scanning.
func parseChainOps(cmd string) chainParse {
	var segments []chainSegment
	var buf strings.Builder
	hasNestedOps := false
	inSingle, inDouble := false, false
	parenDepth := 0

	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]

		// Backslash escapes the next character outside single quotes.
		// - Outside quotes: \' \", \\ etc. prevent the next char from being special.
		// - Inside double quotes: \" \\ \$ \` are special escapes.
		// - Inside single quotes: \ is literal (bash rule), so we skip this.
		if ch == '\\' && !inSingle && i+1 < len(cmd) {
			buf.WriteByte(ch)
			i++
			buf.WriteByte(cmd[i])
			continue
		}

		// Single quotes: no escaping inside (bash rule).
		// '\'' pattern (end quote, escaped quote, start quote) is handled
		// naturally — the first ' ends the single-quoted region.
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
		}

		// Outside quotes: track paren depth and detect operators
		if !inSingle && !inDouble {
			// Track $() and () nesting so we only split at the top level.
			// $((expr)) arithmetic also works — depth increments twice.
			if ch == '(' {
				parenDepth++
			}
			if ch == ')' && parenDepth > 0 {
				parenDepth--
			}

			if i+1 < len(cmd) {
				pair := cmd[i : i+2]
				if pair == "&&" || pair == "||" {
					if parenDepth == 0 {
						// Top-level chain operator — split here.
						segments = append(segments, chainSegment{
							Text: strings.TrimSpace(buf.String()),
							Op:   pair,
						})
						buf.Reset()
						i++ // skip second character
						continue
					} else {
						// Chain op inside $() or () — PS 5.1 can't handle this,
						// so the entire command must be delegated to git-bash/cmd.exe.
						hasNestedOps = true
					}
				}
			}
		}

		buf.WriteByte(ch)
	}

	// Last segment (no trailing operator)
	segments = append(segments, chainSegment{
		Text: strings.TrimSpace(buf.String()),
	})

	return chainParse{
		Segments:     segments,
		HasNestedOps: hasNestedOps,
	}
}

// hasChainOps is a convenience function that checks if a command contains
// && or || operators outside of quotes. Used by handler.go for warnings.
func hasChainOps(cmd string) bool {
	return parseChainOps(cmd).HasChainOps()
}
