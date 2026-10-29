package analyze

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"agent-tool/common"
)

func commonAllowAnnotationPath(path string) bool {
	if common.GetAllowSymlinks() {
		return true
	}
	// Check existing parents too, including when annotation_set creates the file.
	for {
		fi, err := os.Lstat(path)
		if err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return false
		}
		parent := filepath.Dir(path)
		if parent == path {
			return true
		}
		path = parent
	}
}

func loadAnnotationAddresses(ctx context.Context, input AnalyzeInput, addresses []string) (map[string][]analysisAnnotation, string, error) {
	s, err := openAnnotations(ctx, input, false)
	if err != nil {
		return nil, "", fmt.Errorf("load annotations: %w", err)
	}
	if s == nil {
		return nil, "", nil
	}
	defer s.db.Close()
	notes, more, err := s.atAddresses(ctx, addresses)
	if err != nil {
		return nil, "", fmt.Errorf("read annotations: %w", err)
	}
	notice := ""
	if more {
		notice = "User annotations limited to 500 records; use annotation_list with va/query and result_offset to read more."
	}
	return notes, notice, nil
}

func annotationLoadWarning(err error) string {
	message := []rune(err.Error())
	if len(message) > 1024 {
		message = append(message[:1024], []rune("...")...)
	}
	return "WARNING: user annotations unavailable: " + strconv.Quote(string(message)) + "; analysis continues without user notes."
}

func disassemblyLineVA(line string) string {
	addr, _, ok := strings.Cut(line, ":")
	if !ok || !strings.HasPrefix(addr, "0x") {
		return ""
	}
	va, err := parseHexAddr(addr)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%016x", va)
}

func renderDisassemblyAnnotations(ctx context.Context, input AnalyzeInput, text string) (string, error) {
	lines := strings.Split(text, "\n")
	addresses := make([]string, 0, len(lines))
	seen := map[string]bool{}
	for _, line := range lines {
		if va := disassemblyLineVA(line); va != "" && !seen[va] {
			seen[va] = true
			addresses = append(addresses, va)
		}
	}
	notes, notice, err := loadAnnotationAddresses(ctx, input, addresses)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		notes, notice = nil, annotationLoadWarning(err)
	}
	if len(notes) == 0 && notice == "" {
		return pageOutput(text, input.ResultOffset, input.MaxOutputChars, "disassemble"), nil
	}
	var sb strings.Builder
	if notice != "" {
		sb.WriteString("; " + notice + "\n")
	}
	for i, line := range lines {
		if i != 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(line)
		for _, a := range notes[disassemblyLineVA(line)] {
			if a.Kind == "instruction" || a.Kind == "function" {
				sb.WriteString("  ; " + annotationText(a))
			}
		}
	}
	return pageOutput(sb.String(), input.ResultOffset, input.MaxOutputChars, "disassemble"), nil
}
