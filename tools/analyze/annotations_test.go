package analyze

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-tool/common"
)

type annotationReply struct {
	Path    string               `json:"annotations_path"`
	Hash    string               `json:"binary_sha256"`
	Items   []analysisAnnotation `json:"annotations"`
	Next    *int                 `json:"next_result_offset"`
	Deleted bool                 `json:"deleted"`
}

func annotationCall(t *testing.T, in AnalyzeInput) annotationReply {
	t.Helper()
	result, out, err := Handle(context.Background(), nil, in)
	if err != nil || result.IsError {
		t.Fatalf("annotation %s failed: %v / %s", in.Operation, err, out.Result)
	}
	var reply annotationReply
	if err := json.Unmarshal([]byte(out.Result), &reply); err != nil {
		t.Fatalf("invalid annotation JSON: %v / %s", err, out.Result)
	}
	return reply
}

func annotationTestInput(t *testing.T) AnalyzeInput {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(bin, []byte{0x48, 0x89, 0xc8, 0xc3}, 0o600); err != nil {
		t.Fatal(err)
	}
	return AnalyzeInput{FilePath: bin, AnnotationsPath: filepath.Join(dir, "notes #1.sqlite"), VA: "0x20000000000001",
		Comment: "rax points to User", Subject: "rax", AnnotationStatus: "hypothesis"}
}

func TestAnnotationsPersistenceIdentityAndCRUD(t *testing.T) {
	in := annotationTestInput(t)
	in.Operation = "annotation_set"
	saved := annotationCall(t, in)
	if len(saved.Items) != 1 || len(saved.Hash) != 64 || saved.Items[0].VA != in.VA {
		t.Fatalf("identity/address lost: %+v", saved)
	}
	id := saved.Items[0].ID
	// Each call reopens the SQLite file: persistence is not an in-memory cache.
	in.Comment = "현재 사용자 포인터"
	in.AnnotationStatus = "confirmed"
	updated := annotationCall(t, in)
	if updated.Items[0].ID != id || updated.Items[0].Comment != in.Comment {
		t.Fatalf("upsert did not preserve ID: %+v", updated)
	}
	// A copy at a different path has the same content identity.
	copyPath := filepath.Join(filepath.Dir(in.FilePath), "moved.bin")
	data, _ := os.ReadFile(in.FilePath)
	if err := os.WriteFile(copyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	in.FilePath, in.Operation, in.Query = copyPath, "annotation_list", "현재"
	list := annotationCall(t, in)
	if len(list.Items) != 1 || list.Hash != saved.Hash {
		t.Fatalf("copy/search lost annotation: %+v", list)
	}
	// Changed content, even the same size, must not inherit or delete old notes.
	if err := os.WriteFile(copyPath, []byte{0x48, 0x89, 0xc1, 0xc3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := annotationCall(t, in); len(got.Items) != 0 || got.Hash == saved.Hash {
		t.Fatalf("changed binary inherited annotations: %+v", got)
	}
	in.Operation, in.AnnotationID = "annotation_delete", id
	result, _, _ := Handle(context.Background(), nil, in)
	if !result.IsError {
		t.Fatal("delete reached a different binary")
	}
	in.Operation, in.Comment, in.Label = "annotation_set", "wrong binary", ""
	result, _, _ = Handle(context.Background(), nil, in)
	if !result.IsError {
		t.Fatal("update reached a different binary")
	}
	if err := os.WriteFile(copyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	in.Operation, in.Comment = "annotation_set", "edited by ID"
	if got := annotationCall(t, in); got.Items[0].ID != id || got.Items[0].Comment != in.Comment {
		t.Fatalf("edit by ID: %+v", got)
	}
	in.Operation = "annotation_delete"
	if !annotationCall(t, in).Deleted {
		t.Fatal("not deleted")
	}
	in.Operation, in.Query, in.AnnotationID = "annotation_list", "", ""
	if got := annotationCall(t, in); len(got.Items) != 0 {
		t.Fatalf("delete did not persist: %+v", got)
	}
}

func TestAnnotationsCustomPathAndDisassembly(t *testing.T) {
	in := annotationTestInput(t)
	in.VA, in.Operation = "0x0", "annotation_set"
	in.Comment = "rax = User*\nsecond line"
	annotationCall(t, in)
	dis := AnalyzeInput{FilePath: in.FilePath, AnnotationsPath: in.AnnotationsPath, Count: 2}
	result, out, err := Handle(context.Background(), nil, AnalyzeInput{
		Operation: "disassemble", FilePath: dis.FilePath, AnnotationsPath: dis.AnnotationsPath, Count: 2,
	})
	if err != nil || result.IsError || !strings.Contains(out.Result, "user:hypothesis") ||
		!strings.Contains(out.Result, `subject="rax"`) || !strings.Contains(out.Result, `\nsecond line`) {
		t.Fatalf("disassembly annotation missing/unsafe: %v / %s", err, out.Result)
	}
	// Relative annotation paths follow the request workspace.
	previous := common.GetWorkspace()
	common.SetWorkspace(filepath.Dir(in.FilePath))
	defer common.SetWorkspace(previous)
	in.Operation, in.AnnotationsPath = "annotation_list", filepath.Base(in.AnnotationsPath)
	if len(annotationCall(t, in).Items) != 1 {
		t.Fatal("relative path did not load selected DB")
	}
	in.AnnotationsPath = filepath.Join(filepath.Dir(in.FilePath), "missing.sqlite")
	in.Operation = "annotation_list"
	if result, _, _ := Handle(context.Background(), nil, in); !result.IsError {
		t.Fatal("missing explicit DB silently accepted")
	}
	if _, err := os.Stat(in.AnnotationsPath); !os.IsNotExist(err) {
		t.Fatal("read created a database")
	}
}

func TestAnnotationsDecompileSnapshotAndLineRendering(t *testing.T) {
	in := annotationTestInput(t)
	code := "int f(void)\n{\n  return 7;\n}\n"
	in.Operation, in.VA = "annotation_set", "0x140001000"
	in.AnnotationKind, in.Line, in.CodeHash = "decompile", 3, decompileCodeHash(code)
	in.Comment = "return value is a status code"
	saved := annotationCall(t, in)
	// Loading through the same rendering path as opDecompile.
	notes, _, err := loadAnnotationAddresses(context.Background(), in, []string{"0000000140001000"})
	if err != nil {
		t.Fatal(err)
	}
	input := AnalyzeInput{FilePath: in.FilePath, LineNumbers: true, annotations: notes}
	lines := []decompileLine{{Kind: "load", Format: "PE", Spec: "x86:LE:64"}, {
		Kind: "result", Target: "f", Entry: 0x140001000, Name: "f", C: code,
	}}
	out := formatDecompile(input, []string{"f"}, lines, "", 0)
	if !strings.Contains(out, "// L3 user:hypothesis") || !strings.Contains(out, "/* L3 */   return 7;") ||
		!strings.Contains(out, "code_hash="+in.CodeHash) {
		t.Fatalf("line annotation missing:\n%s", out)
	}
	lines[1].C = "int f(void)\n{\n  int x = 8;\n  return x;\n}\n"
	out = formatDecompile(input, []string{"f"}, lines, "", 0)
	if !strings.Contains(out, "user:needs_review id="+saved.Items[0].ID) || strings.Contains(out, "// L3 user:hypothesis") {
		t.Fatalf("stale comment attached to changed C:\n%s", out)
	}
	// Function-level notes render without line numbering, independent of C changes.
	in.AnnotationID, in.AnnotationKind, in.Line, in.CodeHash = "", "function", 0, ""
	in.Label, in.Comment = "read_status", "function summary"
	annotationCall(t, in)
	notes, _, err = loadAnnotationAddresses(context.Background(), in, []string{"0000000140001000"})
	if err != nil {
		t.Fatal(err)
	}
	out = renderAnnotatedC(lines[1].C, notes["0000000140001000"], false)
	if !strings.Contains(out, `label="read_status"`) || strings.Contains(out, "/* L") {
		t.Fatalf("function note missing: %s", out)
	}
}

func TestAnnotationsPagingAndValidation(t *testing.T) {
	in := annotationTestInput(t)
	in.Operation = "annotation_set"
	annotationCall(t, in)
	in.VA, in.Subject = "0x20000000000002", ""
	annotationCall(t, in)
	in.VA, in.Operation, in.MaxResults = "", "annotation_list", 1
	first := annotationCall(t, in)
	if len(first.Items) != 1 || first.Next == nil || *first.Next != 1 {
		t.Fatalf("first page: %+v", first)
	}
	in.ResultOffset = *first.Next
	second := annotationCall(t, in)
	if len(second.Items) != 1 || second.Next != nil || second.Items[0].ID == first.Items[0].ID {
		t.Fatalf("second page: %+v", second)
	}
	for _, change := range []func(*AnalyzeInput){
		func(i *AnalyzeInput) { i.AnnotationKind = "decompile"; i.Line = 2 },
		func(i *AnalyzeInput) { i.Line = 3 },
		func(i *AnalyzeInput) { i.AnnotationStatus = "certain" },
		func(i *AnalyzeInput) { i.Comment = ""; i.Label = "" },
		func(i *AnalyzeInput) { i.RVA = "0x1000" },
	} {
		bad := in
		bad.Operation, bad.VA, bad.ResultOffset = "annotation_set", "0x10", 0
		change(&bad)
		if result, _, _ := Handle(context.Background(), nil, bad); !result.IsError {
			t.Fatalf("invalid annotation accepted: %+v", bad)
		}
	}
}

func TestAnnotationsRejectForeignDB(t *testing.T) {
	in := annotationTestInput(t)
	db, err := sql.Open("sqlite", in.AnnotationsPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("CREATE TABLE important_data (value TEXT)")
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	in.Operation = "annotation_set"
	if result, _, _ := Handle(context.Background(), nil, in); !result.IsError {
		t.Fatal("modified unrelated SQLite database")
	}
	db, _ = sql.Open("sqlite", in.AnnotationsPath)
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='analysis_annotations'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("foreign DB changed: %d / %v", count, err)
	}
}

func TestAnnotationsWorkerIntegration(t *testing.T) {
	exe, err := filepath.Abs(filepath.Join("testdata", "pdb", "fixture_x64.exe"))
	if err != nil {
		t.Fatal(err)
	}
	input := AnalyzeInput{Operation: "decompile", FilePath: exe, VA: "use_node", LineNumbers: true}
	result, out, err := Handle(context.Background(), nil, input)
	if err != nil || result.IsError {
		t.Fatalf("decompile: %v / %s", err, out.Result)
	}
	_, rest, ok := strings.Cut(out.Result, "code_hash=")
	if !ok || len(rest) < 64 {
		t.Fatalf("worker output has no line anchor: %s", out.Result)
	}
	db := filepath.Join(t.TempDir(), "worker.sqlite")
	note := AnalyzeInput{Operation: "annotation_set", FilePath: exe, VA: "use_node",
		AnnotationsPath: db, AnnotationKind: "decompile", Line: 1, CodeHash: rest[:64],
		Comment: "worker round trip", Subject: "n", AnnotationStatus: "confirmed"}
	saved := annotationCall(t, note)
	input.AnnotationsPath = db
	result, out, err = Handle(context.Background(), nil, input)
	if err != nil || result.IsError || !strings.Contains(out.Result, "// L1 user:confirmed id="+saved.Items[0].ID) {
		t.Fatalf("worker did not reload selected database: %v / %s", err, out.Result)
	}
	// Reading a later page uses the same raw-C line anchors.
	input.ResultOffset, input.MaxOutputChars = 100, 200
	result, out, err = Handle(context.Background(), nil, input)
	if err != nil || result.IsError || !strings.Contains(out.Result, "result_offset=300") {
		t.Fatalf("annotated paging failed: %v / %s", err, out.Result)
	}
}

func TestAnnotationsDefaultReadDoesNotCreateDB(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	in := annotationTestInput(t)
	in.Operation, in.AnnotationsPath = "annotation_list", ""
	path, err := annotationsPath(in)
	if err != nil {
		t.Fatal(err)
	}
	annotationCall(t, in)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("default read created durable data")
	}
	in.Operation = "annotation_set"
	if got := annotationCall(t, in); got.Path != path {
		t.Fatalf("default path differs: %+v", got)
	}
}

func TestAnnotationsPERVA(t *testing.T) {
	exe, err := filepath.Abs(filepath.Join("testdata", "pdb", "fixture_x64.exe"))
	if err != nil {
		t.Fatal(err)
	}
	in := AnalyzeInput{Operation: "annotation_set", FilePath: exe, RVA: "0x1074", AnnotationKind: "function",
		Label: "user_node_handler", AnnotationsPath: filepath.Join(t.TempDir(), "project.sqlite")}
	saved := annotationCall(t, in)
	if saved.Items[0].VA != "0x140001074" {
		t.Fatalf("incorrect image base: %+v", saved)
	}
	in.Operation, in.RVA, in.VA = "annotation_list", "", "use_node"
	if len(annotationCall(t, in).Items) != 1 {
		t.Fatal("symbol and RVA did not identify same address")
	}
	dis := AnalyzeInput{FilePath: exe, VA: "0x140001074", AnnotationsPath: in.AnnotationsPath, Count: 2}
	text, err := opDisassemble(dis)
	if err != nil || !strings.Contains(text, `label="user_node_handler"`) {
		t.Fatalf("PE RVA note not rendered: %v / %s", err, text)
	}
}
