package analyze

import (
	"bytes"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const maxXrefTextStrings = 16

// xrefString is one stored string that contains the searched text. Code
// references point at a string's first byte, not at the matched words, so
// va is the start of the enclosing string.
type xrefString struct {
	va      uint64
	section string
	wide    bool
	text    string
}

// findXrefStrings locates text in the data sections as UTF-8/ASCII and as
// UTF-16LE (wchar_t literals on Windows), widening each match to its
// enclosing NUL-terminated string.
func findXrefStrings(bin *xrefBinary, text string) []xrefString {
	narrow := []byte(text)
	wide := make([]byte, 0, 2*len(text))
	for _, u := range utf16.Encode([]rune(text)) {
		wide = append(wide, byte(u), byte(u>>8))
	}
	var out []xrefString
	seen := map[uint64]bool{}
	add := func(sec xrefDataSection, start int, isWide bool) {
		va := bin.imageBase + uint64(sec.rva) + uint64(start)
		if seen[va] || len(out) >= maxXrefTextStrings {
			return
		}
		seen[va] = true
		out = append(out, xrefString{va: va, section: sec.name, wide: isWide, text: readCString(sec.data[start:], isWide)})
	}
	for _, sec := range bin.dataSections {
		for from := 0; len(out) < maxXrefTextStrings; {
			i := bytes.Index(sec.data[from:], narrow)
			if i < 0 {
				break
			}
			at := from + i
			start := at
			for start > 0 && sec.data[start-1] != 0 && at-start < 4096 {
				start--
			}
			add(sec, start, false)
			from = at + len(narrow)
		}
		for from := 0; len(out) < maxXrefTextStrings; {
			i := bytes.Index(sec.data[from:], wide)
			if i < 0 {
				break
			}
			at := from + i
			from = at + len(wide)
			if at%2 != 0 {
				continue // wchar_t literals are 2-byte aligned
			}
			start := at
			for start >= 2 && (sec.data[start-1] != 0 || sec.data[start-2] != 0) && at-start < 8192 {
				start -= 2
			}
			add(sec, start, true)
		}
	}
	return out
}

// readCString reads a NUL-terminated string for display, at most 120 runes.
func readCString(b []byte, wide bool) string {
	var sb strings.Builder
	n := 0
	if wide {
		for i := 0; i+1 < len(b) && n < 120; i += 2 {
			u := uint16(b[i]) | uint16(b[i+1])<<8
			if u == 0 {
				break
			}
			sb.WriteRune(rune(u))
			n++
		}
	} else {
		end := bytes.IndexByte(b, 0)
		if end < 0 {
			end = len(b)
		}
		s := b[:end]
		for len(s) > 0 && n < 120 {
			r, size := utf8.DecodeRune(s)
			sb.WriteRune(r)
			s = s[size:]
			n++
		}
	}
	return sb.String()
}
