package analyze

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
)

type annotationCandidate struct {
	Line       int    `json:"line"`
	AnchorText string `json:"anchor_text"`
	Score      int    `json:"score"`
	Reason     string `json:"reason"`
}

func annotationTokens(text string) map[string]bool {
	tokens := strings.FieldsFunc(text, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' })
	out := map[string]bool{}
	for _, token := range tokens {
		out[token] = true
	}
	return out
}

func annotationCandidates(a analysisAnnotation, code string) ([]annotationCandidate, string) {
	lines := strings.Split(strings.TrimSuffix(canonicalC(code), "\n"), "\n")
	out := []annotationCandidate{}
	if a.CodeHash == decompileCodeHash(code) && a.Line > 0 && a.Line <= len(lines) && len(lines[a.Line-1]) <= 2048 {
		return append(out, annotationCandidate{Line: a.Line, AnchorText: lines[a.Line-1], Score: 100, Reason: "unchanged_snapshot"}), ""
	}
	anchor := strings.Join(strings.Fields(a.AnchorText), " ")
	tokens := annotationTokens(anchor)
	if len(tokens) == 0 || len(anchor) < 6 {
		return out, "No distinctive stored anchor_text; select a line manually."
	}
	for i, line := range lines {
		if len(line) > 2048 {
			continue
		}
		normalized := strings.Join(strings.Fields(line), " ")
		if normalized == anchor {
			out = append(out, annotationCandidate{Line: i + 1, AnchorText: line, Score: 100, Reason: "normalized_text_match"})
			continue
		}
		if len(tokens) < 3 {
			continue
		}
		current := annotationTokens(line)
		common := 0
		for token := range tokens {
			if current[token] {
				common++
			}
		}
		union := len(tokens) + len(current) - common
		if union > 0 {
			score := 100 * common / union
			if score >= 65 {
				out = append(out, annotationCandidate{Line: i + 1, AnchorText: line, Score: score, Reason: "token_overlap_unverified"})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Line < out[j].Line
	})
	if len(out) > 3 {
		out = out[:3]
	}
	if len(out) == 0 {
		return out, "No sufficiently similar line; select a line manually."
	}
	return out, "Candidates are unverified suggestions. Review the C before updating the note."
}

func opAnnotationSuggest(ctx context.Context, input AnalyzeInput) (string, error) {
	if input.AnnotationID == "" {
		return "", fmt.Errorf("annotation_id is required")
	}
	s, err := openAnnotations(ctx, input, false)
	if err != nil {
		return "", err
	}
	if s == nil {
		return "", fmt.Errorf("annotation database not found")
	}
	defer s.db.Close()
	a, err := scanAnnotation(s.db.QueryRowContext(ctx, "SELECT "+s.columns()+" FROM analysis_annotations WHERE id=? AND binary_sha256=?", input.AnnotationID, s.hash))
	if err != nil {
		return "", err
	}
	if a.Kind != "decompile" {
		return "", fmt.Errorf("annotation_suggest requires a decompile annotation")
	}
	timeout := input.TimeoutSec
	if timeout <= 0 {
		timeout = decompileDefaultTimeout
	}
	if timeout > decompileMaxTimeout {
		return "", fmt.Errorf("timeout_sec must be at most %d", decompileMaxTimeout)
	}
	target := "0x" + a.VA
	lines, failure := runDecompileWorker(ctx, decompileRequest{Path: input.FilePath, Targets: []string{target},
		MemLimitMB: decompileMemLimitMB, PDBPath: input.PDBPath, PDBForce: input.PDBForce}, time.Duration(timeout)*time.Second)
	var result *decompileLine
	for i := range lines {
		if lines[i].Error != "" {
			failure = lines[i].Error
		}
		if lines[i].Kind == "result" && lines[i].Target == target && lines[i].Error == "" {
			result = &lines[i]
		}
	}
	if result == nil {
		return "", fmt.Errorf("could not decompile annotation function: %s", failure)
	}
	if fmt.Sprintf("%016x", result.Entry) != a.VA {
		return "", fmt.Errorf("stored VA is not the resolved function entry; re-anchor manually")
	}
	hash, err := binarySHA256(ctx, input.FilePath)
	if err != nil {
		return "", err
	}
	if hash != s.hash {
		return "", fmt.Errorf("binary changed while generating suggestions; retry with stable input")
	}
	candidates, notice := annotationCandidates(a, result.C)
	payload := map[string]any{"annotation_id": a.ID, "expected_revision": a.Revision, "function_va": target,
		"code_hash": decompileCodeHash(result.C), "requires_confirmation": true, "candidates": candidates, "notice": notice}
	if len(candidates) > 1 && candidates[0].Score == candidates[1].Score {
		payload["ambiguous"] = true
	}
	data, _ := json.MarshalIndent(payload, "", "  ")
	capChars := input.MaxOutputChars
	if capChars <= 0 {
		capChars = defaultAnalyzeOutputChars
	}
	if len([]rune(string(data))) > capChars {
		return "", fmt.Errorf("suggestions exceed max_output_chars; raise it")
	}
	return string(data), nil
}
