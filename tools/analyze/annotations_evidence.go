package analyze

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// These are user-supplied evidence records, never automatically fetched or verified.
type AnnotationEvidence struct {
	Kind   string `json:"kind" jsonschema:"static, runtime, or user; records the origin of the observation, not verification"`
	VA     string `json:"va,omitempty" jsonschema:"Optional static address as an exact hex string"`
	Source string `json:"source,omitempty" jsonschema:"Source description or reference; never fetched automatically"`
	Detail string `json:"detail" jsonschema:"Observation supporting the note"`
}

func validateAnnotationID(id string) error {
	if len(id) != 32 {
		return fmt.Errorf("annotation_id must be the exact 32-character ID from set/list")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return fmt.Errorf("invalid annotation_id")
	}
	return nil
}

func annotationEvidenceJSON(evidence []AnnotationEvidence) string {
	if evidence == nil {
		return "[]"
	}
	data, _ := json.Marshal(evidence)
	return string(data)
}

func validateAnnotationEvidence(a *analysisAnnotation) error {
	if len(a.Evidence) > 16 || len(a.Provenance) > 512 || len(a.AnchorText) > 2048 {
		return fmt.Errorf("annotation metadata limits: 16 evidence records, provenance 512 bytes, anchor_text 2048 bytes")
	}
	if a.AnchorText != "" && (a.Kind != "decompile" || strings.ContainsAny(a.AnchorText, "\r\n")) {
		return fmt.Errorf("anchor_text must be one raw C line for a decompile annotation")
	}
	for i := range a.Evidence {
		e := &a.Evidence[i]
		if e.Kind != "static" && e.Kind != "runtime" && e.Kind != "user" {
			return fmt.Errorf("evidence kind must be static, runtime or user")
		}
		if strings.TrimSpace(e.Detail) == "" || len(e.Detail) > 1024 || len(e.Source) > 512 {
			return fmt.Errorf("evidence needs detail (max 1024 bytes); source max 512 bytes")
		}
		if e.VA != "" {
			v, err := parseHexAddr(e.VA)
			if err != nil {
				return fmt.Errorf("evidence va must be an exact hex address")
			}
			e.VA = fmt.Sprintf("0x%x", v)
		}
	}
	return nil
}
