package analyze

import (
	"context"
	"database/sql"
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnnotationsBatchAndEvidence(t *testing.T) {
	in := annotationTestInput(t)
	in.Operation = "annotation_batch"
	in.Batch = []AnnotationBatchItem{
		{Operation: "set", VA: "0x0", Comment: "entry", Provenance: "manual review", Evidence: []AnnotationEvidence{{Kind: "static", VA: "0x20000000000001", Source: "call graph", Detail: "Returned from lookup"}}},
		{Operation: "set", VA: "0x3", Comment: "return"},
		{Operation: "unsupported"},
		{Operation: "set", VA: "0x0", Comment: "must not overwrite"},
	}
	result, out, err := Handle(context.Background(), nil, in)
	if err != nil || result.IsError {
		t.Fatalf("batch: %v / %s", err, out.Result)
	}
	var reply struct {
		Results           []annotationBatchReceipt
		Succeeded, Failed int
	}
	if err := json.Unmarshal([]byte(out.Result), &reply); err != nil || reply.Succeeded != 2 || reply.Failed != 2 || len(reply.Results) != 4 {
		t.Fatalf("batch receipts: %s / %v", out.Result, err)
	}
	if reply.Results[0].Revision != "1" || reply.Results[2].Error == "" || reply.Results[3].Error == "" {
		t.Fatalf("bad item status: %s", out.Result)
	}
	list := AnalyzeInput{Operation: "annotation_list", FilePath: in.FilePath, AnnotationsPath: in.AnnotationsPath, Query: "call graph"}
	saved := annotationCall(t, list)
	if len(saved.Items) != 1 || saved.Items[0].Evidence[0].VA != "0x20000000000001" || saved.Items[0].Provenance != "manual review" {
		t.Fatalf("evidence not persisted/searchable: %+v", saved)
	}
	in.Batch = []AnnotationBatchItem{
		{Operation: "set", AnnotationID: reply.Results[0].ID, ExpectedRevision: "1", Comment: "updated"},
		{Operation: "set", AnnotationID: reply.Results[0].ID, ExpectedRevision: "1", Comment: "stale"},
		{Operation: "delete", AnnotationID: reply.Results[1].ID, ExpectedRevision: "1"},
	}
	result, out, err = Handle(context.Background(), nil, in)
	if err != nil || result.IsError {
		t.Fatalf("batch mutation: %v / %s", err, out.Result)
	}
	if err := json.Unmarshal([]byte(out.Result), &reply); err != nil || reply.Succeeded != 2 || reply.Failed != 1 {
		t.Fatalf("partial conflicts: %s / %v", out.Result, err)
	}
	if reply.Results[0].Revision != "2" || !reply.Results[2].Deleted {
		t.Fatalf("revision/delete: %s", out.Result)
	}
	if got := annotationCall(t, list); len(got.Items) != 1 || got.Items[0].Comment != "updated" || len(got.Items[0].Evidence) != 1 {
		t.Fatalf("partial batch lost evidence: %+v", got)
	}
	patch := AnalyzeInput{Operation: "annotation_set", FilePath: in.FilePath, AnnotationsPath: in.AnnotationsPath,
		AnnotationID: reply.Results[0].ID, ExpectedRevision: "2", AnnotationPatch: &AnnotationPatch{Evidence: annotationPointer([]AnnotationEvidence{}), Provenance: annotationPointer("")}}
	if got := annotationCall(t, patch).Items[0]; len(got.Evidence) != 0 || got.Provenance != "" {
		t.Fatalf("explicit clearing failed: %+v", got)
	}
	// Too-small aggregate receipt budgets fail before any item commits.
	in.MaxOutputChars = 256
	result, _, _ = Handle(context.Background(), nil, in)
	if !result.IsError {
		t.Fatal("undersized batch budget accepted")
	}
	in.Batch = make([]AnnotationBatchItem, 33)
	in.MaxOutputChars = 0
	result, _, _ = Handle(context.Background(), nil, in)
	if !result.IsError {
		t.Fatal("oversized batch accepted")
	}
}

func TestAnnotationsFunctionInteriorAndNeighborIsolation(t *testing.T) {
	exe, _ := filepath.Abs(filepath.Join("testdata", "pdb", "fixture_x64.exe"))
	entry, err := lookupSymbolVA(exe, "", false, "use_node")
	if err != nil {
		t.Fatal(err)
	}
	neighbor, err := lookupSymbolVA(exe, "", false, "sum_points")
	if err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "scope.sqlite")
	for _, item := range []struct {
		va      uint64
		comment string
	}{{entry, "entry note"}, {entry + 1, "interior proof"}, {neighbor, "neighbor secret note"}} {
		annotationCall(t, AnalyzeInput{Operation: "annotation_set", FilePath: exe, AnnotationsPath: db, VA: fmt.Sprintf("0x%x", item.va), Comment: item.comment})
	}
	result, out, err := Handle(context.Background(), nil, AnalyzeInput{Operation: "decompile", FilePath: exe, AnnotationsPath: db, VA: "use_node"})
	if err != nil || result.IsError || !strings.Contains(out.Result, "interior proof") || !strings.Contains(out.Result, "exact function range") ||
		strings.Contains(out.Result, "neighbor secret note") {
		t.Fatalf("function scope not isolated: %v / %s", err, out.Result)
	}
}

func TestAnnotationsSuggestionAndConfirmedReanchor(t *testing.T) {
	exe, _ := filepath.Abs(filepath.Join("testdata", "pdb", "fixture_x64.exe"))
	lines, failure := runDecompileWorker(context.Background(), decompileRequest{Path: exe, Targets: []string{"use_node"}, MemLimitMB: decompileMemLimitMB}, 30_000_000_000)
	var current decompileLine
	for _, line := range lines {
		if line.Kind == "result" && line.Error == "" {
			current = line
		}
	}
	if current.C == "" {
		t.Fatalf("fixture decompile: %s", failure)
	}
	raw := strings.Split(strings.TrimSuffix(canonicalC(current.C), "\n"), "\n")
	selected := 0
	for i, line := range raw {
		if strings.Contains(line, "n->") && len(line) <= 2048 {
			selected = i
			break
		}
	}
	db := filepath.Join(t.TempDir(), "suggest.sqlite")
	note := AnalyzeInput{Operation: "annotation_set", FilePath: exe, AnnotationsPath: db, VA: fmt.Sprintf("0x%x", current.Entry),
		AnnotationKind: "decompile", Line: 1, CodeHash: decompileCodeHash("old snapshot"), AnchorText: raw[selected], Comment: "keep this meaning"}
	saved := annotationCall(t, note).Items[0]
	result, out, err := Handle(context.Background(), nil, AnalyzeInput{Operation: "annotation_suggest", FilePath: exe, AnnotationsPath: db, AnnotationID: saved.ID})
	if err != nil || result.IsError {
		t.Fatalf("suggest: %v / %s", err, out.Result)
	}
	var suggestions struct {
		CodeHash   string                `json:"code_hash"`
		Revision   string                `json:"expected_revision"`
		Confirm    bool                  `json:"requires_confirmation"`
		Candidates []annotationCandidate `json:"candidates"`
	}
	if err := json.Unmarshal([]byte(out.Result), &suggestions); err != nil || !suggestions.Confirm || len(suggestions.Candidates) == 0 || suggestions.Revision != "1" {
		t.Fatalf("suggestions missing: %s / %v", out.Result, err)
	}
	query := AnalyzeInput{Operation: "annotation_list", FilePath: exe, AnnotationsPath: db, AnnotationID: saved.ID}
	unchanged := annotationCall(t, query).Items[0]
	if unchanged.CodeHash != note.CodeHash || unchanged.Revision != "1" {
		t.Fatal("suggestion moved note without confirmation")
	}
	c := suggestions.Candidates[0]
	applied := annotationCall(t, AnalyzeInput{Operation: "annotation_set", FilePath: exe, AnnotationsPath: db, AnnotationID: saved.ID, ExpectedRevision: suggestions.Revision,
		AnnotationPatch: &AnnotationPatch{Line: &c.Line, CodeHash: &suggestions.CodeHash, AnchorText: &c.AnchorText}}).Items[0]
	if applied.Revision != "2" || applied.CodeHash != decompileCodeHash(current.C) || applied.Comment != note.Comment {
		t.Fatalf("confirmed reanchor failed: %+v", applied)
	}
	code := renderAnnotatedC(current.C, []analysisAnnotation{applied}, true)
	if strings.Contains(code, "needs_review") || !strings.Contains(code, "// L") {
		t.Fatalf("reanchored rendering: %s", code)
	}
}

func TestAnnotationsSuggestionAmbiguityAndLegacyFallback(t *testing.T) {
	code := "int f() {\n  result = lookup_user(id);\n  result = lookup_user(id);\n}\n"
	a := analysisAnnotation{CodeHash: decompileCodeHash("old"), AnchorText: "result = lookup_user(id);"}
	candidates, _ := annotationCandidates(a, code)
	if len(candidates) != 2 || candidates[0].Score != 100 || candidates[1].Score != 100 {
		t.Fatalf("ambiguous candidates: %+v", candidates)
	}
	a.AnchorText = ""
	candidates, notice := annotationCandidates(a, code)
	if len(candidates) != 0 || !strings.Contains(notice, "manually") {
		t.Fatalf("invented legacy candidate: %+v / %s", candidates, notice)
	}
	a.AnchorText = "result = lookup_user(id, old_flags);"
	candidates, _ = annotationCandidates(a, code)
	if len(candidates) == 0 || candidates[0].Reason != "token_overlap_unverified" {
		t.Fatalf("fuzzy candidate: %+v", candidates)
	}
}

func TestAnnotationsEvidenceLiteralSearch(t *testing.T) {
	in := annotationTestInput(t)
	in.Operation = "annotation_set"
	detail := "rax < 10 && pointer->field > 0; source \"quoted\" C:\\trace"
	in.Evidence = []AnnotationEvidence{{Kind: "static", Source: detail, Detail: detail}}
	annotationCall(t, in)
	in.Operation = "annotation_list"
	for _, query := range []string{"rax < 10", "&&", "pointer->field", "> 0", "\"quoted\"", "C:\\trace"} {
		in.Query = query
		if got := annotationCall(t, in); len(got.Items) != 1 {
			t.Fatalf("literal evidence query %q lost record: %+v", query, got)
		}
	}
}

func TestAnnotationsFailedFunctionsSkipRanges(t *testing.T) {
	in := annotationTestInput(t)
	in.AnnotationsPath = filepath.Join(t.TempDir(), "missing.sqlite")
	notes, notice, err := loadFunctionAnnotations(context.Background(), in, []decompileLine{{Kind: "result", Error: "input error"}})
	if err != nil || len(notes) != 0 || notice != "" {
		t.Fatalf("failed functions still load annotation DB/ranges: %v / %s", err, notice)
	}
}

func TestAnnotationsExactPdataAndELFScopes(t *testing.T) {
	exe, _ := filepath.Abs(filepath.Join("testdata", "pdb", "fixture_x64.exe"))
	entry, err := lookupSymbolVA(exe, "", false, "use_node")
	if err != nil {
		t.Fatal(err)
	}
	// Disable PDB so this path must use exact .pdata boundaries.
	in := AnalyzeInput{Operation: "annotation_set", FilePath: exe, PDBPath: "none", AnnotationsPath: filepath.Join(t.TempDir(), "pdata.sqlite"),
		VA: fmt.Sprintf("0x%x", entry+1), Comment: "pdata interior"}
	annotationCall(t, in)
	notes, _, err := loadFunctionAnnotations(context.Background(), in, []decompileLine{{Kind: "result", Entry: entry}})
	if err != nil || len(notes[fmt.Sprintf("%016x", entry)]) != 1 {
		t.Fatalf("exact pdata scope: %v / %+v", err, notes)
	}
	dir := t.TempDir()
	src, bin := filepath.Join(dir, "main.go"), filepath.Join(dir, "fixture")
	if err := os.WriteFile(src, []byte("package main\n//go:noinline\nfunc sample(x int) int { return x+1 }\nfunc main(){ println(sample(3)) }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ELF fixture: %v / %s", err, output)
	}
	f, err := elf.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	syms, err := f.Symbols()
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	var start, end uint64
	for _, sym := range syms {
		if sym.Name == "main.sample" {
			start, end = sym.Value, sym.Value+sym.Size
		}
	}
	if start == 0 || end <= start+1 {
		t.Fatal("no sized ELF function")
	}
	in.FilePath, in.AnnotationsPath, in.PDBPath = bin, filepath.Join(dir, "elf.sqlite"), ""
	for _, item := range []struct {
		va      uint64
		comment string
	}{{start + 1, "ELF interior"}, {end, "ELF end outside"}} {
		in.VA, in.Comment = fmt.Sprintf("0x%x", item.va), item.comment
		annotationCall(t, in)
	}
	notes, _, err = loadFunctionAnnotations(context.Background(), in, []decompileLine{{Kind: "result", Entry: start}})
	got := notes[fmt.Sprintf("%016x", start)]
	if err != nil || len(got) != 1 || got[0].Comment != "ELF interior" {
		t.Fatalf("ELF exclusive boundary: %v / %+v", err, got)
	}
}

func TestAnnotationsV2MetadataMigration(t *testing.T) {
	in := annotationTestInput(t)
	in.Operation = "annotation_set"
	saved := annotationCall(t, in).Items[0]
	db, _ := sql.Open("sqlite", in.AnnotationsPath)
	_, err := db.Exec("ALTER TABLE analysis_annotations DROP COLUMN evidence; ALTER TABLE analysis_annotations DROP COLUMN provenance; ALTER TABLE analysis_annotations DROP COLUMN anchor_text; PRAGMA user_version=2")
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	in.Operation = "annotation_list"
	legacy := annotationCall(t, in)
	if len(legacy.Items) != 1 || legacy.Items[0].Revision != "1" || len(legacy.Items[0].Evidence) != 0 {
		t.Fatalf("v2 read: %+v", legacy)
	}
	in.Operation, in.AnnotationID, in.ExpectedRevision = "annotation_set", saved.ID, "1"
	in.Provenance = "new evidence after migration"
	in.Evidence = []AnnotationEvidence{{Kind: "runtime", Detail: "Observed during a controlled run"}}
	updated := annotationCall(t, in).Items[0]
	if updated.Revision != "2" || updated.Provenance != in.Provenance || len(updated.Evidence) != 1 {
		t.Fatalf("v3 migration: %+v", updated)
	}
}
