package edit

import "strings"

// This is lexical evidence, not a language parser. Only a block opener followed
// by a deeper code line votes. Continuations and opaque literals never vote.
// An inconclusive scan leaves the existing content/configuration fallback intact.
func structuralIndentWidth(content string, anchor int) (int, bool) {
	const maxSample = 8 * 1024 * 1024
	if anchor >= maxSample {
		return 0, false
	}
	anchorLine := -1
	if anchor >= 0 {
		anchorLine = strings.Count(content[:anchor], "\n")
	}
	var lexer indentLexer
	var votes [9]int
	prevIndent, prevLine, prevPos := 0, 0, 0
	prevOpens, prevSpaces := false, false
	pos, lineNo := 0, 0
	nearest := 33
	for line := range indentLines(content) {
		if anchorLine >= 0 && lineNo > anchorLine+32 {
			break
		}
		prefixLen := len(line) - len(strings.TrimLeft(line, " \t"))
		spaces := !strings.Contains(line[:prefixLen], "\t")
		code, opens, continued := lexer.scan(line[prefixLen:])
		if code {
			if prevOpens && !continued && spaces && prevSpaces {
				width := prefixLen - prevIndent
				weight := 1
				if anchorLine >= 0 {
					distance := prevLine - anchorLine
					if distance < 0 {
						distance = -distance
					}
					byteDistance := prevPos - anchor
					if byteDistance < 0 {
						byteDistance = -byteDistance
					}
					if byteDistance > 16*1024 || distance > 32 || distance > nearest {
						weight = 0
					} else if width > 0 && width <= 8 {
						// A nearby minority-style block must not be outvoted by
						// numerous more distant blocks. Equal-distance conflicts
						// remain inconclusive.
						if distance < nearest {
							votes = [9]int{}
							nearest = distance
						}
					}
				}
				if width > 0 && width <= 8 && weight > 0 {
					votes[width] += weight
				}
			}
			prevIndent, prevLine, prevPos = prefixLen, lineNo, pos
			prevOpens, prevSpaces = opens, spaces
		}
		pos += len(line) + 1 // local anchors use the LF-normalized view
		lineNo++
	}
	best, total := 0, 0
	for width := 1; width <= 8; width++ {
		total += votes[width]
		if votes[width] > votes[best] {
			best = width
		}
	}
	// No arbitrary tie-breaking or statistically calibrated confidence claim.
	return best, best > 0 && votes[best]*2 > total
}

func localIndentWidth(content string, anchor, fallback int) int {
	if width, ok := structuralIndentWidth(content, anchor); ok {
		return width
	}
	return fallback
}

// A compact cross-language lexer recognizes common comments/literals. It does
// not interpret template interpolation, macros or embedded languages.
type indentLexer struct {
	blockComment  bool
	quote         byte
	triple        bool
	verbatim      bool
	rawEnd        string
	round, square int
	splice        bool
	directive     bool
}

func (l *indentLexer) scan(line string) (code, opens, continued bool) {
	// A preprocessor directive and its continued physical lines are opaque.
	if l.directive || (!l.blockComment && l.quote == 0 && l.rawEnd == "" && strings.HasPrefix(line, "#")) {
		l.directive = strings.HasSuffix(strings.TrimRight(line, " \t"), "\\")
		return false, false, false
	}
	wasSpliced := l.splice
	continued = l.round > 0 || l.square > 0 || wasSpliced
	l.splice = false
	// Only the first identifier and last code byte are needed. Do not retain
	// whole long lines or allocate once per character inside multiline literals.
	var first [16]byte
	wordLen := 0
	wordDone := false
	var last byte
	emit := func(c byte) {
		if c == ' ' || c == '\t' {
			if wordLen > 0 {
				wordDone = true
			}
			return
		}
		if !wordDone {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' {
				if wordLen < len(first) {
					first[wordLen] = c
					wordLen++
				}
			} else {
				wordDone = true
			}
		}
		last = c
	}
	for i := 0; i < len(line); {
		if l.rawEnd != "" {
			end := strings.Index(line[i:], l.rawEnd)
			if end < 0 {
				break
			}
			i += end + len(l.rawEnd)
			l.rawEnd = ""
			continue
		}
		if l.blockComment {
			end := strings.Index(line[i:], "*/")
			if end < 0 {
				break
			}
			i += end + 2
			l.blockComment = false
			continue
		}
		if l.quote != 0 {
			q := l.quote
			if l.triple && i+2 < len(line) && line[i] == q && line[i+1] == q && line[i+2] == q {
				i += 3
				l.quote, l.triple = 0, false
			} else if !l.triple && line[i] == q {
				if l.verbatim && i+1 < len(line) && line[i+1] == q {
					i += 2
				} else {
					i++
					l.quote, l.verbatim = 0, false
				}
			} else if line[i] == '\\' && !l.verbatim && q != '`' {
				i += 2
			} else {
				i++
			}
			continue
		}
		c := line[i]
		if c == '#' || strings.HasPrefix(line[i:], "//") {
			break
		}
		if strings.HasPrefix(line[i:], "/*") {
			l.blockComment = true
			i += 2
			continue
		}
		// C++ raw strings: the delimiter is at most 16 characters.
		if strings.HasPrefix(line[i:], "R\"") {
			limit := min(len(line), i+2+17)
			if end := strings.IndexByte(line[i+2:limit], '('); end >= 0 {
				delim := line[i+2 : i+2+end]
				if !strings.ContainsAny(delim, " \t\\)\r\n") {
					l.rawEnd = ")" + delim + "\""
					emit('x')
					i += 3 + end
					continue
				}
			}
		}
		if c == '\'' || c == '"' || c == '`' {
			l.quote = c
			l.verbatim = c == '"' && i > 0 && line[i-1] == '@'
			l.triple = c != '`' && i+2 < len(line) && line[i+1] == c && line[i+2] == c
			emit('x')
			i++
			if l.triple {
				i += 2
			}
			continue
		}
		switch c {
		case '(':
			l.round++
		case ')':
			if l.round > 0 {
				l.round--
			}
		case '[':
			l.square++
		case ']':
			if l.square > 0 {
				l.square--
			}
		}
		emit(c)
		i++
	}
	l.splice = last == '\\'
	// Ordinary quoted literals end at a physical line unless explicitly spliced.
	// Backticks, triple quotes, raw and verbatim literals may span lines.
	if l.quote != 0 && l.quote != '`' && !l.triple && !l.verbatim {
		// A trailing escape continues a C-style literal onto the next line.
		n := 0
		for i := len(line) - 1; i >= 0 && line[i] == '\\'; i-- {
			n++
		}
		if n%2 == 0 {
			l.quote = 0
		}
	}
	code = last != 0
	if !code || l.round > 0 || l.square > 0 || l.splice || wasSpliced {
		return code, false, continued
	}
	opens = last == '{'
	if last == ':' {
		switch string(first[:wordLen]) {
		case "if", "elif", "else", "for", "while", "def", "class", "try", "except", "finally", "with", "match", "case", "async":
			opens = true
		}
	}
	return code, opens, continued
}
