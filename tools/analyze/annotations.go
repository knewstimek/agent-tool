package analyze

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

// User knowledge is durable data, never part of the evictable analysis cache.
// Addresses and IDs remain strings through SQLite, JSON and MCP.
const annotationAppID = 0x4154414e
const annotationLimit = 200

type analysisAnnotation struct {
	ID       string `json:"id"`
	VA       string `json:"va"`
	Kind     string `json:"kind"`
	Subject  string `json:"subject,omitempty"`
	Label    string `json:"label,omitempty"`
	Comment  string `json:"comment,omitempty"`
	Status   string `json:"status"`
	Line     int    `json:"line,omitempty"`
	CodeHash string `json:"code_hash,omitempty"`
	Revision string `json:"revision"`
}

type annotationStore struct {
	db      *sql.DB
	hash    string
	path    string
	version int
}

func annotationsPath(input AnalyzeInput) (string, error) {
	if input.AnnotationsPath != "" {
		return filepath.Abs(input.AnnotationsPath)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "agent-tool", "analysis-annotations.sqlite"), nil
}

func binarySHA256(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	buf := make([]byte, 128*1024)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, readErr := f.Read(buf)
		h.Write(buf[:n])
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	after, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", fmt.Errorf("binary changed while computing annotation identity; retry with a stable file")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Reads never create a database. A missing explicitly selected DB is an error.
func openAnnotations(ctx context.Context, input AnalyzeInput, write bool) (*annotationStore, error) {
	path, err := annotationsPath(input)
	if err != nil {
		return nil, err
	}
	if !commonAllowAnnotationPath(path) {
		return nil, fmt.Errorf("annotation database symlinks are not allowed")
	}
	fi, statErr := os.Stat(path)
	exists := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return nil, statErr
	}
	if exists && fi.IsDir() {
		return nil, fmt.Errorf("annotations_path must name a SQLite file")
	}
	if exists {
		binaryInfo, err := os.Stat(input.FilePath)
		if err != nil {
			return nil, err
		}
		if os.SameFile(fi, binaryInfo) {
			return nil, fmt.Errorf("annotations_path must not be the analyzed binary")
		}
	}
	create := write && strings.EqualFold(strings.TrimSpace(input.Operation), "annotation_set")
	if !exists && !create {
		if input.AnnotationsPath != "" {
			return nil, fmt.Errorf("annotation database not found; annotation_set creates it")
		}
		return nil, nil
	}
	if write {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
	}
	// A URI prevents '?' and '#' in a user-selected filename becoming DSN options.
	uriPath := filepath.ToSlash(path)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	if write {
		u.RawQuery = "mode=rwc"
	} else {
		u.RawQuery = "mode=ro"
	}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*annotationStore, error) { db.Close(); return nil, err }
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		return fail(err)
	}
	var appID int
	if err := db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return fail(err)
	}
	if appID == 0 && create {
		var tables int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
			return fail(err)
		}
		if tables != 0 {
			return fail(fmt.Errorf("annotations_path contains another database; choose an annotation database"))
		}
		if _, err := db.ExecContext(ctx, `
			BEGIN IMMEDIATE;
			CREATE TABLE IF NOT EXISTS analysis_annotations (
				id TEXT PRIMARY KEY,
				binary_sha256 TEXT NOT NULL,
				va TEXT NOT NULL,
				kind TEXT NOT NULL,
				subject TEXT NOT NULL,
				label TEXT NOT NULL,
				comment TEXT NOT NULL,
				status TEXT NOT NULL,
				line INTEGER NOT NULL,
				code_hash TEXT NOT NULL,
				revision INTEGER NOT NULL DEFAULT 1,
				UNIQUE(binary_sha256, va, kind, subject, line, code_hash)
			);
			PRAGMA application_id=1096040782;
			PRAGMA user_version=2;
			COMMIT;`); err != nil {
			return fail(err)
		}
		appID = annotationAppID
	}
	if appID != annotationAppID {
		return fail(fmt.Errorf("annotations_path is not an AgentTool annotation database"))
	}
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if version != 1 && version != 2 {
		return fail(fmt.Errorf("unsupported annotation database version %d", version))
	}
	if version == 1 && write {
		if err := migrateAnnotationRevision(ctx, db); err != nil {
			return fail(err)
		}
		version = 2
	}
	hash, err := binarySHA256(ctx, input.FilePath)
	if err != nil {
		return fail(err)
	}
	return &annotationStore{db: db, hash: hash, path: path, version: version}, nil
}

func annotationVA(input AnalyzeInput) (string, error) {
	if input.RVA != "" {
		if input.VA != "" {
			return "", fmt.Errorf("provide va or rva, not both")
		}
		f, err := pe.Open(input.FilePath)
		if err != nil {
			return "", fmt.Errorf("rva for annotations requires a PE image; use va for other formats")
		}
		defer f.Close()
		rva, err := parseHexAddr(input.RVA)
		if err != nil {
			return "", fmt.Errorf("invalid rva: %w", err)
		}
		base := peImageBase(f)
		if rva > ^uint64(0)-base {
			return "", fmt.Errorf("rva overflows the image address")
		}
		return fmt.Sprintf("%016x", base+rva), nil
	}
	if strings.TrimSpace(input.VA) == "" {
		return "", fmt.Errorf("va (hex or symbol) or PE rva is required")
	}
	va, err := parseHexAddr(input.VA)
	if err != nil {
		va, err = lookupSymbolVA(input.FilePath, input.PDBPath, input.PDBForce, input.VA)
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%016x", va), nil
}

func makeAnnotation(input AnalyzeInput) (analysisAnnotation, error) {
	a := analysisAnnotation{ID: input.AnnotationID, Kind: input.AnnotationKind, Subject: input.Subject,
		Label: input.Label, Comment: input.Comment, Status: input.AnnotationStatus, Line: input.Line,
		CodeHash: strings.ToLower(input.CodeHash)}
	if a.Kind == "" {
		a.Kind = "instruction"
	}
	if a.Status == "" {
		a.Status = "hypothesis"
	}
	if a.Kind != "instruction" && a.Kind != "function" && a.Kind != "decompile" {
		return a, fmt.Errorf("annotation_kind must be instruction, function or decompile")
	}
	if a.Status != "hypothesis" && a.Status != "confirmed" && a.Status != "rejected" {
		return a, fmt.Errorf("annotation_status must be hypothesis, confirmed or rejected")
	}
	if strings.TrimSpace(a.Label) == "" && strings.TrimSpace(a.Comment) == "" {
		return a, fmt.Errorf("label or comment is required")
	}
	if len(a.Label) > 256 || len(a.Subject) > 256 || len(a.Comment) > 8192 {
		return a, fmt.Errorf("annotation limit: label/subject 256 bytes, comment 8192 bytes")
	}
	if a.Kind == "decompile" {
		decoded, err := hex.DecodeString(a.CodeHash)
		if a.Line <= 0 || err != nil || len(decoded) != sha256.Size {
			return a, fmt.Errorf("decompile annotation needs line >= 1 and the code_hash from decompile line_numbers=true")
		}
	} else if a.Line != 0 || a.CodeHash != "" {
		return a, fmt.Errorf("line and code_hash are only for annotation_kind=decompile")
	}
	va, err := annotationVA(input)
	a.VA = va
	return a, err
}

const annotationColumns = "id, va, kind, subject, label, comment, status, line, code_hash"

func scanAnnotation(row interface{ Scan(...any) error }) (analysisAnnotation, error) {
	var a analysisAnnotation
	err := row.Scan(&a.ID, &a.VA, &a.Kind, &a.Subject, &a.Label, &a.Comment, &a.Status, &a.Line, &a.CodeHash, &a.Revision)
	return a, err
}

func (s *annotationStore) create(ctx context.Context, a analysisAnnotation) (analysisAnnotation, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return a, err
	}
	a.ID = hex.EncodeToString(id)
	return scanAnnotation(s.db.QueryRowContext(ctx, `INSERT INTO analysis_annotations
		(id,binary_sha256,va,kind,subject,label,comment,status,line,code_hash)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(binary_sha256,va,kind,subject,line,code_hash) DO NOTHING
		RETURNING `+s.columns(),
		a.ID, s.hash, a.VA, a.Kind, a.Subject, a.Label, a.Comment, a.Status, a.Line, a.CodeHash))
}

func opAnnotations(ctx context.Context, input AnalyzeInput) (string, error) {
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	var a analysisAnnotation
	var err error
	if op == "annotation_set" && input.AnnotationID == "" {
		if input.ExpectedRevision != "" || input.AnnotationPatch != nil {
			return "", fmt.Errorf("expected_revision and annotation_patch require annotation_id")
		}
		a, err = makeAnnotation(input)
		if err != nil {
			return "", err
		}
	}
	if op == "annotation_delete" && input.AnnotationID == "" {
		return "", fmt.Errorf("annotation_id is required; use annotation_list to find it")
	}
	if (op == "annotation_set" && input.AnnotationID != "") || op == "annotation_delete" {
		if err := validateAnnotationRevision(input.ExpectedRevision); err != nil {
			return "", err
		}
	}
	if op != "annotation_list" && input.MaxOutputChars > 0 && input.MaxOutputChars < 256 {
		return "", fmt.Errorf("max_output_chars must be at least 256 for annotation writes; nothing was changed")
	}
	if len(input.Query) > 512 {
		return "", fmt.Errorf("query must be at most 512 bytes")
	}
	limit := input.MaxResults
	if limit <= 0 {
		limit = 50
	}
	if limit > annotationLimit {
		return "", fmt.Errorf("max_results for annotations must be at most %d", annotationLimit)
	}
	s, err := openAnnotations(ctx, input, op == "annotation_set" || op == "annotation_delete")
	if err != nil {
		return "", err
	}
	items := []analysisAnnotation{}
	var deleted bool
	path, _ := annotationsPath(input)
	hash := ""
	more := false
	if s != nil {
		defer s.db.Close()
		path, hash = s.path, s.hash
		switch op {
		case "annotation_set":
			if input.AnnotationID != "" {
				a, err = s.update(ctx, input)
			} else {
				a, err = s.create(ctx, a)
				if err == sql.ErrNoRows {
					err = fmt.Errorf("annotation anchor already exists; use annotation_list, then annotation_id and expected_revision to update")
				}
			}
			items = append(items, a)
		case "annotation_delete":
			var result sql.Result
			result, err = s.db.ExecContext(ctx, "DELETE FROM analysis_annotations WHERE binary_sha256=? AND id=? AND revision=?", s.hash, input.AnnotationID, input.ExpectedRevision)
			if err == nil {
				var n int64
				n, err = result.RowsAffected()
				deleted = n != 0
				if !deleted && err == nil {
					err = fmt.Errorf("annotation not found for this binary or revision conflict; reread annotation_list before retrying")
				}
			}
		case "annotation_list":
			where := "binary_sha256=?"
			args := []any{s.hash}
			if input.AnnotationID != "" {
				where += " AND id=?"
				args = append(args, input.AnnotationID)
			}
			if input.VA != "" || input.RVA != "" {
				va, e := annotationVA(input)
				if e != nil {
					return "", e
				}
				where += " AND va=?"
				args = append(args, va)
			}
			for _, filter := range []struct{ col, value string }{
				{"kind", input.AnnotationKind}, {"subject", input.Subject}, {"status", input.AnnotationStatus},
			} {
				if filter.value != "" {
					where += " AND " + filter.col + "=?"
					args = append(args, filter.value)
				}
			}
			if input.Query != "" {
				where += " AND instr(lower(label || char(10) || comment || char(10) || subject),lower(?))>0"
				args = append(args, input.Query)
			}
			args = append(args, limit+1, input.ResultOffset)
			var rows *sql.Rows
			rows, err = s.db.QueryContext(ctx, "SELECT "+s.columns()+" FROM analysis_annotations WHERE "+where+
				" ORDER BY va,kind,line,subject,code_hash,id LIMIT ? OFFSET ?", args...)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					a, err = scanAnnotation(rows)
					if err != nil {
						break
					}
					items = append(items, a)
				}
				if err == nil {
					err = rows.Err()
				}
				if len(items) > limit {
					items, more = items[:limit], true
				}
			}
		}
	} else if op == "annotation_delete" {
		return "", fmt.Errorf("annotation_id not found for this binary")
	}
	if err != nil {
		return "", err
	}
	for i := range items {
		items[i].VA = "0x" + strings.TrimLeft(items[i].VA, "0")
		if items[i].VA == "0x" {
			items[i].VA = "0x0"
		}
	}
	payload := map[string]any{"annotations_path": path, "binary_sha256": hash, "annotations": items}
	if op == "annotation_delete" {
		payload["deleted"] = deleted
		payload["annotation_id"] = input.AnnotationID
	} else if op == "annotation_set" {
		payload["saved"] = true
	}
	if more {
		payload["next_result_offset"] = input.ResultOffset + len(items)
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	// Keep JSON valid and row paging independent of character paging.
	capChars := input.MaxOutputChars
	if capChars <= 0 {
		capChars = defaultAnalyzeOutputChars
	}
	for len([]rune(string(data))) > capChars && len(items) > 1 {
		items = items[:len(items)-1]
		payload["annotations"] = items
		if op == "annotation_list" {
			payload["next_result_offset"] = input.ResultOffset + len(items)
		}
		data, err = json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return "", err
		}
	}
	if len([]rune(string(data))) > capChars {
		if op == "annotation_list" {
			return "", fmt.Errorf("annotation output exceeds max_output_chars; raise it")
		}
		// Every committed mutation gets an unambiguous bounded success receipt.
		receipt := map[string]any{"details_omitted": true}
		if op == "annotation_set" {
			receipt["saved"], receipt["annotation_id"], receipt["revision"] = true, a.ID, a.Revision
		} else {
			receipt["deleted"], receipt["annotation_id"] = true, input.AnnotationID
		}
		data, _ = json.Marshal(receipt)
	}
	return string(data), nil
}

// Fetch only notes at addresses actually displayed; one bounded SQL query.
func (s *annotationStore) atAddresses(ctx context.Context, addresses []string) (map[string][]analysisAnnotation, bool, error) {
	out := map[string][]analysisAnnotation{}
	if len(addresses) == 0 {
		return out, false, nil
	}
	args := []any{s.hash}
	for _, va := range addresses {
		args = append(args, va)
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+s.columns()+" FROM analysis_annotations WHERE binary_sha256=? AND va IN ("+
		strings.TrimSuffix(strings.Repeat("?,", len(addresses)), ",")+") ORDER BY va,kind,line,subject,id LIMIT 501", args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		a, err := scanAnnotation(rows)
		if err != nil {
			return nil, false, err
		}
		n++
		if n > 500 {
			return out, true, nil
		}
		out[a.VA] = append(out[a.VA], a)
	}
	return out, false, rows.Err()
}

func annotationText(a analysisAnnotation) string {
	parts := []string{"user:" + a.Status, "id=" + a.ID, "revision=" + a.Revision}
	if a.Subject != "" {
		parts = append(parts, "subject="+strconv.Quote(a.Subject))
	}
	if a.Label != "" {
		parts = append(parts, "label="+strconv.Quote(a.Label))
	}
	if a.Comment != "" {
		parts = append(parts, strconv.Quote(a.Comment))
	}
	// Quotes escape newlines/control characters: notes cannot impersonate code.
	return strings.Join(parts, " ")
}

func canonicalC(code string) string {
	return strings.TrimLeft(strings.ReplaceAll(code, "\r\n", "\n"), "\n")
}

func decompileCodeHash(code string) string {
	hash := sha256.Sum256([]byte(canonicalC(code)))
	return hex.EncodeToString(hash[:])
}

func renderAnnotatedC(code string, notes []analysisAnnotation, numbered bool) string {
	code = canonicalC(code)
	lines := strings.Split(strings.TrimSuffix(code, "\n"), "\n")
	hash := decompileCodeHash(code)
	perLine := map[int][]analysisAnnotation{}
	var sb strings.Builder
	if numbered {
		fmt.Fprintf(&sb, "// annotation anchor: code_hash=%s; line is the L number in this C body\n", hash)
	}
	for _, a := range notes {
		switch a.Kind {
		case "function":
			fmt.Fprintf(&sb, "// %s\n", annotationText(a))
		case "decompile":
			if a.CodeHash == hash && a.Line > 0 && a.Line <= len(lines) {
				perLine[a.Line] = append(perLine[a.Line], a)
			} else {
				fmt.Fprintf(&sb, "// user:needs_review id=%s line=%d code_hash=%s (C snapshot changed or line missing): %s\n",
					a.ID, a.Line, a.CodeHash, annotationText(a))
			}
		case "instruction":
			fmt.Fprintf(&sb, "// instruction note at function entry (no C source mapping): %s\n", annotationText(a))
		}
	}
	for i, line := range lines {
		for _, a := range perLine[i+1] {
			fmt.Fprintf(&sb, "// L%d %s\n", i+1, annotationText(a))
		}
		if numbered {
			fmt.Fprintf(&sb, "/* L%d */ ", i+1)
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return sb.String()
}
