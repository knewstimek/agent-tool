package analyze

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

// Pointer fields distinguish omitted values from explicit empty text or line=0.
type AnnotationPatch struct {
	Label      *string               `json:"label,omitempty"`
	Comment    *string               `json:"comment,omitempty"`
	Subject    *string               `json:"subject,omitempty"`
	Status     *string               `json:"annotation_status,omitempty"`
	Kind       *string               `json:"annotation_kind,omitempty"`
	VA         *string               `json:"va,omitempty"`
	RVA        *string               `json:"rva,omitempty"`
	Line       *int                  `json:"line,omitempty"`
	CodeHash   *string               `json:"code_hash,omitempty"`
	Evidence   *[]AnnotationEvidence `json:"evidence,omitempty"`
	Provenance *string               `json:"provenance,omitempty"`
	AnchorText *string               `json:"anchor_text,omitempty"`
}

func (s *annotationStore) columns() string {
	if s.version == 1 {
		return annotationColumns + ", '1' AS revision, '[]' AS evidence, '' AS provenance, '' AS anchor_text"
	}
	if s.version == 2 {
		return annotationColumns + ", CAST(revision AS TEXT), '[]' AS evidence, '' AS provenance, '' AS anchor_text"
	}
	return annotationColumns + ", CAST(revision AS TEXT), evidence, provenance, anchor_text"
}

// Read-only v1 databases remain readable. The first write migrates in-place,
// atomically, checking the version again under the SQLite write lock.
func migrateAnnotationRevision(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	var version int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version == 1 {
		if _, err := conn.ExecContext(ctx, "ALTER TABLE analysis_annotations ADD COLUMN revision INTEGER NOT NULL DEFAULT 1"); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "PRAGMA user_version=2"); err != nil {
			return err
		}
		version = 2
	}
	if version == 2 {
		if _, err := conn.ExecContext(ctx, "ALTER TABLE analysis_annotations ADD COLUMN evidence TEXT NOT NULL DEFAULT '[]'; ALTER TABLE analysis_annotations ADD COLUMN provenance TEXT NOT NULL DEFAULT ''; ALTER TABLE analysis_annotations ADD COLUMN anchor_text TEXT NOT NULL DEFAULT ''; PRAGMA user_version=3"); err != nil {
			return err
		}
	} else if version != 3 {
		return fmt.Errorf("unsupported annotation database version %d", version)
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	return err
}

func validateAnnotationRevision(revision string) error {
	n, err := strconv.ParseInt(revision, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != revision {
		return fmt.Errorf("expected_revision must be the exact positive decimal string from annotation_list/set")
	}
	return nil
}

func mergeAnnotation(input AnalyzeInput, old analysisAnnotation) (analysisAnnotation, error) {
	merged := AnalyzeInput{FilePath: input.FilePath, PDBPath: input.PDBPath, PDBForce: input.PDBForce,
		AnnotationID: old.ID, VA: "0x" + old.VA, AnnotationKind: old.Kind, Subject: old.Subject,
		Label: old.Label, Comment: old.Comment, AnnotationStatus: old.Status, Line: old.Line, CodeHash: old.CodeHash, Evidence: old.Evidence, Provenance: old.Provenance, AnchorText: old.AnchorText}
	// Existing nonempty top-level fields remain convenient for partial updates.
	for _, f := range []struct {
		dst   *string
		value string
	}{
		{&merged.AnnotationKind, input.AnnotationKind}, {&merged.Subject, input.Subject},
		{&merged.Label, input.Label}, {&merged.Comment, input.Comment},
		{&merged.AnnotationStatus, input.AnnotationStatus}, {&merged.CodeHash, input.CodeHash},
	} {
		if f.value != "" {
			*f.dst = f.value
		}
	}
	if input.Evidence != nil {
		merged.Evidence = input.Evidence
	}
	if input.Provenance != "" {
		merged.Provenance = input.Provenance
	}
	if input.AnchorText != "" {
		merged.AnchorText = input.AnchorText
	}
	if input.VA != "" || input.RVA != "" {
		merged.VA, merged.RVA = input.VA, input.RVA
	}
	if input.Line != 0 {
		merged.Line = input.Line
	}
	if p := input.AnnotationPatch; p != nil {
		if p.Evidence != nil {
			merged.Evidence = *p.Evidence
		}
		if p.Provenance != nil {
			merged.Provenance = *p.Provenance
		}
		if p.AnchorText != nil {
			merged.AnchorText = *p.AnchorText
		}
		for _, f := range []struct {
			dst   *string
			value *string
		}{
			{&merged.AnnotationKind, p.Kind}, {&merged.Subject, p.Subject}, {&merged.Label, p.Label},
			{&merged.Comment, p.Comment}, {&merged.AnnotationStatus, p.Status}, {&merged.CodeHash, p.CodeHash},
		} {
			if f.value != nil {
				*f.dst = *f.value
			}
		}
		if p.VA != nil || p.RVA != nil {
			merged.VA, merged.RVA = "", ""
			if p.VA != nil {
				merged.VA = *p.VA
			}
			if p.RVA != nil {
				merged.RVA = *p.RVA
			}
		}
		if p.Line != nil {
			merged.Line = *p.Line
		}
	}
	return makeAnnotation(merged)
}

func (s *annotationStore) update(ctx context.Context, input AnalyzeInput) (analysisAnnotation, error) {
	old, err := scanAnnotation(s.db.QueryRowContext(ctx, "SELECT "+s.columns()+
		" FROM analysis_annotations WHERE id=? AND binary_sha256=?", input.AnnotationID, s.hash))
	if err == sql.ErrNoRows {
		return old, fmt.Errorf("annotation_id not found for this binary")
	}
	if err != nil {
		return old, err
	}
	if old.Revision != input.ExpectedRevision {
		return old, fmt.Errorf("annotation revision conflict (current revision=%s); reread annotation_list before retrying", old.Revision)
	}
	if old.Revision == "9223372036854775807" {
		return old, fmt.Errorf("annotation revision exhausted")
	}
	a, err := mergeAnnotation(input, old)
	if err != nil {
		return a, err
	}
	a, err = scanAnnotation(s.db.QueryRowContext(ctx, `UPDATE analysis_annotations
		SET va=?,kind=?,subject=?,label=?,comment=?,status=?,line=?,code_hash=?,evidence=?,provenance=?,anchor_text=?,revision=revision+1
		WHERE id=? AND binary_sha256=? AND revision=? RETURNING `+s.columns(),
		a.VA, a.Kind, a.Subject, a.Label, a.Comment, a.Status, a.Line, a.CodeHash, annotationEvidenceJSON(a.Evidence), a.Provenance, a.AnchorText,
		a.ID, s.hash, input.ExpectedRevision))
	if err == sql.ErrNoRows {
		err = fmt.Errorf("annotation revision conflict; reread annotation_list before retrying")
	}
	return a, err
}
