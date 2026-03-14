package bash

import "strings"

// chainSegment represents a command part between && / || operators.
type chainSegment struct {
	Text string // the command text (trimmed)
	Op   string // operator AFTER this segment: "&&", "||", or "" for last
}

// chainParse holds the result of parsing chain operators from a command.
type chainParse struct {
	Segments  []chainSegment
	HasParens bool // true if ( or ) found outside quotes alongside chain ops
}

// HasChainOps returns true if && or || operators were found outside quotes.
func (p chainParse) HasChainOps() bool {
	return len(p.Segments) > 1
}

// HasGrouping returns true if parenthesized subexpressions exist with chain ops.
// e.g. "(cmd1 && cmd2) || cmd3"
func (p chainParse) HasGrouping() bool {
	return p.HasChainOps() && p.HasParens
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

// parseChainOps tokenizes a bash command, splitting by && and || operators
// while correctly handling:
//   - Single quotes: content is literal, no escaping (bash rule)
//   - Double quotes: backslash escapes \" and \\ (bash rule)
//   - Parentheses outside quotes are detected for grouping
//
// This is the single source of truth for quote-aware chain operator parsing.
// All consumers (hasChainOps, hasGrouping, transformChainOps, handler warnings)
// should use this function instead of ad-hoc string scanning.
func parseChainOps(cmd string) chainParse {
	var segments []chainSegment
	var buf strings.Builder
	hasParens := false
	inSingle, inDouble := false, false

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

		// Outside quotes: detect operators and parentheses
		if !inSingle && !inDouble {
			if i+1 < len(cmd) {
				pair := cmd[i : i+2]
				if pair == "&&" || pair == "||" {
					segments = append(segments, chainSegment{
						Text: strings.TrimSpace(buf.String()),
						Op:   pair,
					})
					buf.Reset()
					i++ // skip second character
					continue
				}
			}
			if ch == '(' || ch == ')' {
				hasParens = true
			}
		}

		buf.WriteByte(ch)
	}

	// Last segment (no trailing operator)
	segments = append(segments, chainSegment{
		Text: strings.TrimSpace(buf.String()),
	})

	return chainParse{
		Segments:  segments,
		HasParens: hasParens,
	}
}

// hasChainOps is a convenience function that checks if a command contains
// && or || operators outside of quotes. Used by handler.go for warnings.
func hasChainOps(cmd string) bool {
	return parseChainOps(cmd).HasChainOps()
}
