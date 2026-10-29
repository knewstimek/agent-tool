package analyze

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func annotationPointer[T any](v T) *T { return &v }

func TestAnnotationsMutationReceipts(t *testing.T) {
	in := annotationTestInput(t)
	in.Operation, in.Comment, in.MaxOutputChars = "annotation_set", strings.Repeat("Long note ", 500), 256
	result, out, err := Handle(context.Background(), nil, in)
	if err != nil || result.IsError || len([]rune(out.Result)) > 256 {
		t.Fatalf("saved mutation reported failure: %v / %s", err, out.Result)
	}
	var receipt struct {
		Saved    bool   `json:"saved"`
		ID       string `json:"annotation_id"`
		Revision string `json:"revision"`
		Omitted  bool   `json:"details_omitted"`
	}
	if err := json.Unmarshal([]byte(out.Result), &receipt); err != nil || !receipt.Saved || receipt.ID == "" || receipt.Revision != "1" || !receipt.Omitted {
		t.Fatalf("invalid success receipt: %+v / %v", receipt, err)
	}
	in.Operation, in.MaxOutputChars, in.AnnotationID = "annotation_list", 0, receipt.ID
	list := annotationCall(t, in)
	if len(list.Items) != 1 || list.Items[0].Comment != in.Comment {
		t.Fatal("short receipt lost stored comment")
	}
	in.Operation, in.MaxOutputChars, in.ExpectedRevision = "annotation_delete", 256, receipt.Revision
	if !annotationCall(t, in).Deleted {
		t.Fatal("delete failed")
	}
	// An impossible response budget is rejected before creating a database.
	bad := annotationTestInput(t)
	bad.Operation, bad.MaxOutputChars = "annotation_set", 20
	result, _, _ = Handle(context.Background(), nil, bad)
	if !result.IsError {
		t.Fatal("impossible receipt budget accepted")
	}
	if _, err := os.Stat(bad.AnnotationsPath); !os.IsNotExist(err) {
		t.Fatal("mutation occurred before output budget validation")
	}
}

func TestAnnotationsPartialUpdatesAndRevisions(t *testing.T) {
	in := annotationTestInput(t)
	in.Operation, in.Label, in.AnnotationStatus = "annotation_set", "user_context", "confirmed"
	saved := annotationCall(t, in).Items[0]
	patch := AnalyzeInput{Operation: "annotation_set", FilePath: in.FilePath, AnnotationsPath: in.AnnotationsPath,
		AnnotationID: saved.ID, ExpectedRevision: saved.Revision, Comment: "updated meaning"}
	updated := annotationCall(t, patch).Items[0]
	if updated.Comment != patch.Comment || updated.Label != saved.Label || updated.Subject != saved.Subject ||
		updated.Status != saved.Status || updated.VA != saved.VA || updated.Revision != "2" {
		t.Fatalf("partial update erased omitted fields: %+v", updated)
	}
	// A stale editor must not overwrite the newer record.
	patch.Comment = "stale content"
	result, out, _ := Handle(context.Background(), nil, patch)
	if !result.IsError || !strings.Contains(out.Result, "revision conflict") {
		t.Fatalf("stale update accepted: %s", out.Result)
	}
	patch.ExpectedRevision = updated.Revision
	patch.Comment = ""
	patch.AnnotationPatch = &AnnotationPatch{Label: annotationPointer(""), Subject: annotationPointer("")}
	cleared := annotationCall(t, patch).Items[0]
	if cleared.Label != "" || cleared.Subject != "" || cleared.Comment != updated.Comment || cleared.Status != "confirmed" || cleared.Revision != "3" {
		t.Fatalf("explicit clearing/omission failed: %+v", cleared)
	}
	// Creation cannot silently bypass the revision guard via the same anchor.
	in.Label, in.Comment, in.Subject = "duplicate", "overwrite", ""
	result, _, _ = Handle(context.Background(), nil, in)
	if !result.IsError {
		t.Fatal("creation silently overwrote existing anchor")
	}
	patch.Operation, patch.ExpectedRevision, patch.AnnotationPatch = "annotation_delete", "2", nil
	if result, _, _ = Handle(context.Background(), nil, patch); !result.IsError {
		t.Fatal("stale delete accepted")
	}
	patch.ExpectedRevision = ""
	if result, _, _ = Handle(context.Background(), nil, patch); !result.IsError {
		t.Fatal("unguarded delete accepted")
	}
	in.Operation, in.AnnotationID, in.VA, in.Subject, in.AnnotationStatus = "annotation_list", saved.ID, "", "", ""
	if got := annotationCall(t, in); len(got.Items) != 1 || got.Items[0].Revision != "3" {
		t.Fatalf("conflicting operations modified the record: %+v", got)
	}
}

func TestAnnotationsConcurrentRevisionUpdate(t *testing.T) {
	in := annotationTestInput(t)
	in.Operation = "annotation_set"
	saved := annotationCall(t, in).Items[0]
	start := make(chan struct{})
	results := make(chan bool, 2)
	var workers sync.WaitGroup
	for _, comment := range []string{"editor one", "editor two"} {
		workers.Add(1)
		go func(comment string) {
			defer workers.Done()
			<-start
			result, _, err := Handle(context.Background(), nil, AnalyzeInput{Operation: "annotation_set",
				FilePath: in.FilePath, AnnotationsPath: in.AnnotationsPath, AnnotationID: saved.ID,
				ExpectedRevision: saved.Revision, Comment: comment})
			results <- err == nil && result != nil && !result.IsError
		}(comment)
	}
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	for success := range results {
		if success {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("same revision accepted %d writers", successes)
	}
}

func TestAnnotationsLegacyMigrationAndExactRevision(t *testing.T) {
	in := annotationTestInput(t)
	in.Operation = "annotation_set"
	saved := annotationCall(t, in).Items[0]
	db, err := sql.Open("sqlite", in.AnnotationsPath)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the previous v1 schema, preserving the original note.
	_, err = db.Exec("ALTER TABLE analysis_annotations DROP COLUMN revision; PRAGMA user_version=1")
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	in.Operation = "annotation_list"
	legacy := annotationCall(t, in)
	if legacy.Items[0].Revision != "1" || legacy.Items[0].Comment != saved.Comment {
		t.Fatalf("read-only legacy compatibility: %+v", legacy)
	}
	db, _ = sql.Open("sqlite", in.AnnotationsPath)
	var version int
	err = db.QueryRow("PRAGMA user_version").Scan(&version)
	db.Close()
	if err != nil || version != 1 {
		t.Fatalf("read migrated DB unexpectedly: %d / %v", version, err)
	}
	patch := AnalyzeInput{Operation: "annotation_set", FilePath: in.FilePath, AnnotationsPath: in.AnnotationsPath,
		AnnotationID: saved.ID, ExpectedRevision: "1", Comment: "migrated"}
	if got := annotationCall(t, patch).Items[0]; got.Revision != "2" || got.Label != saved.Label || got.Subject != saved.Subject {
		t.Fatalf("migration lost fields: %+v", got)
	}
	db, _ = sql.Open("sqlite", in.AnnotationsPath)
	_, err = db.Exec("UPDATE analysis_annotations SET revision=? WHERE id=?", "9007199254740993", saved.ID)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	list := annotationCall(t, in)
	if list.Items[0].Revision != "9007199254740993" {
		t.Fatalf("revision precision lost: %+v", list)
	}
	patch.ExpectedRevision, patch.Comment = list.Items[0].Revision, "exact revision"
	if got := annotationCall(t, patch).Items[0]; got.Revision != "9007199254740994" {
		t.Fatalf("revision precision lost on update: %+v", got)
	}
}

func TestAnnotationsDecompileReanchorPartialPatch(t *testing.T) {
	in := annotationTestInput(t)
	in.Operation, in.AnnotationKind, in.Line = "annotation_set", "decompile", 2
	in.CodeHash = decompileCodeHash("int f() { return 1; }")
	saved := annotationCall(t, in).Items[0]
	hash := decompileCodeHash("int f() { return 2; }")
	patch := AnalyzeInput{Operation: "annotation_set", FilePath: in.FilePath, AnnotationsPath: in.AnnotationsPath,
		AnnotationID: saved.ID, ExpectedRevision: saved.Revision,
		AnnotationPatch: &AnnotationPatch{Line: annotationPointer(1), CodeHash: &hash}}
	updated := annotationCall(t, patch).Items[0]
	if updated.CodeHash != hash || updated.Line != 1 || updated.Comment != saved.Comment || updated.Kind != "decompile" {
		t.Fatalf("reanchor lost note metadata: %+v", updated)
	}
}

func TestAnnotationsLoadFailurePreservesAnalysis(t *testing.T) {
	in := annotationTestInput(t)
	for _, state := range []string{"missing", "corrupt"} {
		t.Run(state, func(t *testing.T) {
			db := filepath.Join(t.TempDir(), "unavailable.sqlite")
			if state == "corrupt" {
				if err := os.WriteFile(db, []byte("not a database"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			result, out, err := Handle(context.Background(), nil, AnalyzeInput{Operation: "disassemble",
				FilePath: in.FilePath, AnnotationsPath: db, Count: 2})
			if err != nil || result.IsError || !strings.Contains(out.Result, "WARNING: user annotations unavailable") ||
				!strings.Contains(out.Result, "0x0:") || !strings.Contains(out.Result, "mov rax, rcx") {
				t.Fatalf("disassembly lost after note failure: %v / %s", err, out.Result)
			}
		})
	}
	exe, _ := filepath.Abs(filepath.Join("testdata", "pdb", "fixture_x64.exe"))
	result, out, err := Handle(context.Background(), nil, AnalyzeInput{Operation: "decompile", FilePath: exe,
		VA: "use_node", AnnotationsPath: filepath.Join(t.TempDir(), "missing.sqlite"), LineNumbers: true})
	if err != nil || result.IsError || !strings.Contains(out.Result, "WARNING: user annotations unavailable") ||
		!strings.Contains(out.Result, "Decompiled 1/1") || !strings.Contains(out.Result, "int use_node(") || !strings.Contains(out.Result, "code_hash=") {
		t.Fatalf("decompilation lost after note failure: %v / %s", err, out.Result)
	}
	// Cancellation remains cancellation, not a successful load warning.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := renderDisassemblyAnnotations(ctx, AnalyzeInput{FilePath: in.FilePath,
		AnnotationsPath: filepath.Join(t.TempDir(), "missing.sqlite")}, "0x0: MOV RAX,RCX"); err != context.Canceled {
		t.Fatalf("cancellation hidden as warning: %v", err)
	}
}
