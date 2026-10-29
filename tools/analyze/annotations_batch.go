package analyze

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// Deliberately excludes paths: every item shares the envelope's binary and DB.
type AnnotationBatchItem struct {
	Operation        string               `json:"operation" jsonschema:"set or delete"`
	AnnotationID     string               `json:"annotation_id,omitempty"`
	ExpectedRevision string               `json:"expected_revision,omitempty"`
	VA               string               `json:"va,omitempty"`
	RVA              string               `json:"rva,omitempty"`
	Kind             string               `json:"annotation_kind,omitempty"`
	Label            string               `json:"label,omitempty"`
	Comment          string               `json:"comment,omitempty"`
	Subject          string               `json:"subject,omitempty"`
	Status           string               `json:"annotation_status,omitempty"`
	Line             int                  `json:"line,omitempty"`
	CodeHash         string               `json:"code_hash,omitempty"`
	AnchorText       string               `json:"anchor_text,omitempty"`
	Evidence         []AnnotationEvidence `json:"evidence,omitempty"`
	Provenance       string               `json:"provenance,omitempty"`
	Patch            *AnnotationPatch     `json:"annotation_patch,omitempty"`
}

type annotationBatchReceipt struct {
	Index    int    `json:"index"`
	Saved    bool   `json:"saved,omitempty"`
	Deleted  bool   `json:"deleted,omitempty"`
	ID       string `json:"annotation_id,omitempty"`
	Revision string `json:"revision,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (b AnnotationBatchItem) input(parent AnalyzeInput) AnalyzeInput {
	return AnalyzeInput{Operation: "annotation_" + b.Operation, FilePath: parent.FilePath,
		PDBPath: parent.PDBPath, PDBForce: parent.PDBForce, AnnotationID: b.AnnotationID,
		ExpectedRevision: b.ExpectedRevision, VA: b.VA, RVA: b.RVA, AnnotationKind: b.Kind,
		Label: b.Label, Comment: b.Comment, Subject: b.Subject, AnnotationStatus: b.Status,
		Line: b.Line, CodeHash: b.CodeHash, AnchorText: b.AnchorText, Evidence: b.Evidence,
		Provenance: b.Provenance, AnnotationPatch: b.Patch}
}

func (s *annotationStore) delete(ctx context.Context, input AnalyzeInput) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM analysis_annotations WHERE binary_sha256=? AND id=? AND revision=?",
		s.hash, input.AnnotationID, input.ExpectedRevision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		err = fmt.Errorf("annotation not found for this binary or revision conflict; reread annotation_list")
	}
	return err
}

func (s *annotationStore) batchItem(ctx context.Context, input AnalyzeInput) (analysisAnnotation, bool, error) {
	if input.Operation != "annotation_set" && input.Operation != "annotation_delete" {
		return analysisAnnotation{}, false, fmt.Errorf("batch operation must be set or delete")
	}
	if input.AnnotationID != "" || input.Operation == "annotation_delete" {
		if input.AnnotationID == "" {
			return analysisAnnotation{}, false, fmt.Errorf("delete requires annotation_id")
		}
		if err := validateAnnotationID(input.AnnotationID); err != nil {
			return analysisAnnotation{}, false, err
		}
		if err := validateAnnotationRevision(input.ExpectedRevision); err != nil {
			return analysisAnnotation{}, false, err
		}
		if input.Operation == "annotation_delete" {
			err := s.delete(ctx, input)
			return analysisAnnotation{ID: input.AnnotationID}, err == nil, err
		}
		a, err := s.update(ctx, input)
		return a, false, err
	}
	if input.ExpectedRevision != "" || input.AnnotationPatch != nil {
		return analysisAnnotation{}, false, fmt.Errorf("expected_revision and annotation_patch require annotation_id")
	}
	a, err := makeAnnotation(input)
	if err == nil {
		a, err = s.create(ctx, a)
	}
	if err == sql.ErrNoRows {
		err = fmt.Errorf("annotation anchor already exists; reread annotation_list and update by ID/revision")
	}
	return a, false, err
}

func opAnnotationBatch(ctx context.Context, input AnalyzeInput) (string, error) {
	n := len(input.Batch)
	if n < 1 || n > 32 {
		return "", fmt.Errorf("batch must contain 1..32 items")
	}
	budget := input.MaxOutputChars
	if budget <= 0 {
		budget = defaultAnalyzeOutputChars
	}
	if budget < 768*n+256 {
		return "", fmt.Errorf("batch needs max_output_chars >= %d for all per-item receipts; nothing changed", 768*n+256)
	}
	writeInput := input
	writeInput.Operation = "annotation_delete"
	for _, item := range input.Batch {
		if item.Operation == "set" {
			writeInput.Operation = "annotation_set"
			break
		}
	}
	s, err := openAnnotations(ctx, writeInput, true)
	if err != nil {
		return "", err
	}
	if s == nil {
		return "", fmt.Errorf("annotation database not found")
	}
	defer s.db.Close()
	receipts := make([]annotationBatchReceipt, 0, n)
	succeeded := 0
	for i, item := range input.Batch {
		r := annotationBatchReceipt{Index: i}
		var a analysisAnnotation
		var deleted bool
		if err = ctx.Err(); err == nil {
			a, deleted, err = s.batchItem(ctx, item.input(input))
		}
		if err != nil {
			// Bounded errors guarantee the preflight receipt budget even on failure.
			detail := []rune(err.Error())
			if len(detail) > 80 {
				detail = detail[:80]
			}
			r.Error = strings.ToValidUTF8(string(detail), "?")
		} else {
			r.ID, r.Revision, r.Deleted, r.Saved = a.ID, a.Revision, deleted, !deleted
			succeeded++
		}
		receipts = append(receipts, r)
	}
	data, _ := json.Marshal(map[string]any{"results": receipts, "succeeded": succeeded, "failed": n - succeeded})
	return string(data), nil
}
