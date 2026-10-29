package analyze

import (
	"context"
	"fmt"
	"os"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultPEImportResults    = 500
	hardPEImportResults       = 100000
	defaultAnalyzeOutputChars = common.DefaultOutputChars
	hardAnalyzeOutputChars    = common.HardOutputChars
)

// AnalyzeInput defines parameters for the static binary analysis tool.
type AnalyzeInput struct {
	Operation string `json:"operation" jsonschema:"Operation: disassemble, instruction_search, pe_info, elf_info, macho_info, strings, hexdump, pattern_search, entropy, bin_diff, resource_info, imphash, rich_header, overlay_detect, dwarf_info, xref, function_at, call_graph, follow_ptr, rtti_dump, struct_layout, vtable_scan, decompile, type_info, annotation_set, annotation_list, annotation_delete, annotation_batch, annotation_suggest,required"`
	FilePath  string `json:"file_path,omitempty" jsonschema:"Binary file path. Relative paths use workspace/MCP root,required"`
	Path      string `json:"path,omitempty" jsonschema:"Alias for file_path"`

	// disassemble / function_at / follow_ptr parameters
	Offset    int         `json:"offset,omitempty" jsonschema:"Byte offset to start from. Default: 0"`
	VA        string      `json:"va,omitempty" jsonschema:"Virtual address: hex (0x140001000) or a symbol name (export, import, PDB/DWARF function or global; name+0x10 adds an offset). For disassemble, function_at, call_graph, follow_ptr, rtti_dump, struct_layout, hexdump. Preferred over offset+base_addr. For decompile: function entries, up to 16 comma-separated."`
	Count     int         `json:"count,omitempty" jsonschema:"Number of instructions (disassemble) or depth (follow_ptr). Default: 50/4, Max: 1000/10. For a large function, raise count or set stop_at_ret=true; if output hits the cap it prints a truncation note with a resume va to continue from."`
	StopAtRet interface{} `json:"stop_at_ret,omitempty" jsonschema:"Stop disassembly at function return (RET/RETF). Confirms boundary via INT3/NOP padding or new prologue. For disassemble only: true or false. Default: false"`
	Mode      int         `json:"mode,omitempty" jsonschema:"CPU mode: 32 or 64. Default: 64"`
	BaseAddr  string      `json:"base_addr,omitempty" jsonschema:"Base address for display (hex string, e.g. '0x140001000'). Default: 0x0. This maps to file offset 0, so displayed address = base_addr + offset + instruction_position. For PE files, prefer 'va' parameter instead -- it auto-calculates the correct base_addr."`
	Arch      string      `json:"arch,omitempty" jsonschema:"CPU architecture: x86 (default) or arm. For disassemble"`

	// strings parameters
	MinLength  int    `json:"min_length,omitempty" jsonschema:"Minimum string length for strings operation. Default: 4"`
	MaxResults int    `json:"max_results,omitempty" jsonschema:"Maximum results. annotation_list: Default 50, Max 200. strings: Default 500, Max 2000. pe_info imports: Default 500, Max 100000"`
	Encoding   string `json:"encoding,omitempty" jsonschema:"String encoding to search for: ascii (default) or utf8"`

	// hexdump parameters
	Length int `json:"length,omitempty" jsonschema:"Number of bytes for hexdump. Default: 256, Max: 4096"`

	// pe_info / elf_info / macho_info parameters
	Section        string `json:"section,omitempty" jsonschema:"Filter by section name (e.g. '.text', '.rdata'). Empty = show all"`
	RVA            string `json:"rva,omitempty" jsonschema:"RVA to convert to file offset (hex string, e.g. '0x36A20'). For pe_info and annotation_set/list; annotations resolve RVA from the PE image base"`
	ResultOffset   int    `json:"result_offset,omitempty" jsonschema:"Paging offset: row index for annotation_list; import index for pe_info; character offset for disassemble, decompile and type_info (a truncated output names the value that continues it). Default: 0"`
	MaxOutputChars int    `json:"max_output_chars,omitempty" jsonschema:"Maximum returned text characters for paged analysis output. Default: 32768, Max: 131072. Annotation writes require at least 256; large write results return a short success receipt."`

	// pattern_search parameters
	Pattern string `json:"pattern,omitempty" jsonschema:"Hex byte pattern with ?? wildcards (e.g. '4D 5A ?? ?? 50 45'). For pattern_search"`

	// instruction_search parameters
	Mnemonic     string `json:"mnemonic,omitempty" jsonschema:"Optional assembly mnemonic filter such as MOV, ADD, or CALL. For instruction_search"`
	Register     string `json:"register,omitempty" jsonschema:"Optional explicit register operand filter such as R9D, EAX, or RCX. For instruction_search"`
	Immediate    string `json:"immediate,omitempty" jsonschema:"Optional immediate value filter in hex or decimal, e.g. 0x327 or 807. For instruction_search"`
	Displacement string `json:"displacement,omitempty" jsonschema:"Optional memory displacement filter (hex or decimal): instructions addressing [reg+0x410] style operands, e.g. who reads or writes a struct field at that offset. For instruction_search"`
	TraceScope   string `json:"trace_scope,omitempty" jsonschema:"Value tracing scope: seeded (default; functions holding the value as an immediate or read-only constant) or all (every function, also values computed from other constants; slower). For instruction_search"`
	TraceValues  *bool  `json:"trace_values,omitempty" jsonschema:"Trace the immediate through bounded function-local register and stack data flow and report matching call arguments. Default: true when immediate is set. For instruction_search"`
	CallTarget   string `json:"call_target,omitempty" jsonschema:"Optional case-insensitive call target symbol/address substring, e.g. DeviceApi or 0x140002000. Requires immediate value tracing. Defaults findings to call. For instruction_search"`
	Findings     string `json:"findings,omitempty" jsonschema:"Result kind: all (default), call (CALL/tail-call value arguments only), or producer (direct instructions and value producers only). For instruction_search"`

	// xref parameters
	TargetVA    string `json:"target_va,omitempty" jsonschema:"Target address to find references to (hex or a symbol name), or inclusive range start when target_end_va is set. For xref operation."`
	TargetEndVA string `json:"target_end_va,omitempty" jsonschema:"Optional inclusive end of the target address range (hex). Omit for an exact-address xref."`
	TargetText  string `json:"target_text,omitempty" jsonschema:"xref: find the stored strings containing this text (UTF-8 and UTF-16LE), then the references to each. Instead of target_va"`
	Field       string `json:"field,omitempty" jsonschema:"xref: structure field as Class::member (offset from the PDB or DWARF; the class as decompile prints it or qualified); lists the functions that access it, confirmed by decompiling candidates. Instead of target_va"`

	// type_info parameters
	TypeName string `json:"type_name,omitempty" jsonschema:"type_info: struct/class/union/enum name as decompile prints it (Node) or qualified (geo::Rect), up to 16 comma-separated; prints members with offsets and enum values from the PDB or DWARF. struct_layout: one type to lay over va (default: the global at va)"`

	// Durable user annotations. Unexported rendering data is not part of MCP.
	AnnotationsPath  string                `json:"annotations_path,omitempty" jsonschema:"SQLite annotation database to save/load. Relative paths use workspace/MCP root. Default: user config dir/agent-tool/analysis-annotations.sqlite. Reads do not create a DB; annotation_set creates it."`
	AnnotationID     string                `json:"annotation_id,omitempty" jsonschema:"Exact string ID from annotation_list/set. set partially updates that record; delete requires it. Both require expected_revision. Records are scoped to the binary SHA-256."`
	Batch            []AnnotationBatchItem `json:"batch,omitempty" jsonschema:"annotation_batch: 1..32 set/delete items for this binary/database. Per-item receipts and conflicts; not an all-or-nothing transaction. Output budget must be at least 768*item_count+256."`
	Evidence         []AnnotationEvidence  `json:"evidence,omitempty" jsonschema:"User-supplied supporting observations (max 16); source references are not fetched or automatically verified."`
	Provenance       string                `json:"provenance,omitempty" jsonschema:"Origin/attribution of the user judgment, max 512 bytes."`
	AnchorText       string                `json:"anchor_text,omitempty" jsonschema:"Optional exact raw C line (max 2048 bytes) for decompile reattachment suggestions; does not bypass code_hash validation. Save it when adding a C-line note."`
	ExpectedRevision string                `json:"expected_revision,omitempty" jsonschema:"Exact revision string from annotation_list/set. Required for updates by annotation_id and deletes; stale revisions are rejected."`
	AnnotationPatch  *AnnotationPatch      `json:"annotation_patch,omitempty" jsonschema:"annotation_set by ID: optional sparse fields; omitted fields are preserved. Explicit empty strings clear text. Patch fields override nonempty top-level fields."`
	AnnotationKind   string                `json:"annotation_kind,omitempty" jsonschema:"instruction (default), function, or decompile. decompile anchors a C-body line to its exact code_hash; function uses the entry VA."`
	Label            string                `json:"label,omitempty" jsonschema:"User label, at most 256 UTF-8 bytes. Annotation metadata only; does not rename engine symbols."`
	Comment          string                `json:"comment,omitempty" jsonschema:"User comment, at most 8192 UTF-8 bytes. New records require label or comment."`
	Subject          string                `json:"subject,omitempty" jsonschema:"Optional register/operand/variable meaning target, e.g. rax or local_10. Scoped to this address/line; metadata only."`
	AnnotationStatus string                `json:"annotation_status,omitempty" jsonschema:"hypothesis (default on set), confirmed, or rejected. User assessment, not engine validation. Also a list filter."`
	Line             int                   `json:"line,omitempty" jsonschema:"1-based C-body L number from decompile line_numbers=true. Required with code_hash for annotation_kind=decompile."`
	CodeHash         string                `json:"code_hash,omitempty" jsonschema:"SHA-256 C snapshot from decompile line_numbers=true. Changed snapshots show needs_review instead of attaching to another line."`
	Query            string                `json:"query,omitempty" jsonschema:"annotation_list: literal case-insensitive substring in label/comment/subject/provenance/evidence (SQLite case folding is ASCII); max 512 bytes."`
	LineNumbers      bool                  `json:"line_numbers,omitempty" jsonschema:"decompile: show C-body L numbers and code_hash for setting line annotations. Numbers exclude headers, notes and type definitions."`
	annotations      map[string][]analysisAnnotation
	annotationNotice string

	// bin_diff parameters
	FilePathB string `json:"file_path_b,omitempty" jsonschema:"Second file for bin_diff. Relative paths use workspace/MCP root"`

	// call_graph parameters are reused from VA + Count fields above

	// decompile parameters (also uses VA)
	TimeoutSec int    `json:"timeout_sec,omitempty" jsonschema:"Seconds before the decompile worker is killed. Default: 60, Max: 600. For decompile"`
	PDBPath    string `json:"pdb_path,omitempty" jsonschema:"PDB for a PE image when it is not beside the binary (must match the image GUID); none disables PDB use. Used by decompile, function_at, follow_ptr, struct_layout, xref; other operations find the PDB automatically"`
	PDBForce   bool   `json:"pdb_force,omitempty" jsonschema:"Load pdb_path even when its GUID does not match the image (relinked or patched build with the same code); output carries a warning. Requires pdb_path"`
}

// Note: follow_ptr uses VA + Count, rtti_dump uses VA, struct_layout uses VA + Length

// AnalyzeOutput holds the tool result.
type AnalyzeOutput struct {
	Result string `json:"result"`
}

var validOperations = map[string]bool{
	"disassemble":        true,
	"instruction_search": true,
	"pe_info":            true,
	"elf_info":           true,
	"macho_info":         true,
	"strings":            true,
	"hexdump":            true,
	"pattern_search":     true,
	"entropy":            true,
	"bin_diff":           true,
	"resource_info":      true,
	"imphash":            true,
	"rich_header":        true,
	"overlay_detect":     true,
	"dwarf_info":         true,
	"xref":               true,
	"function_at":        true,
	"call_graph":         true,
	"follow_ptr":         true,
	"rtti_dump":          true,
	"struct_layout":      true,
	"vtable_scan":        true,
	"decompile":          true,
	"type_info":          true,
	"annotation_set":     true,
	"annotation_list":    true,
	"annotation_delete":  true,
	"annotation_batch":   true,
	"annotation_suggest": true,
}

// Handle dispatches to the appropriate operation.
func Handle(ctx context.Context, req *mcp.CallToolRequest, input AnalyzeInput) (*mcp.CallToolResult, AnalyzeOutput, error) {
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	allOps := "disassemble, instruction_search, pe_info, elf_info, macho_info, strings, hexdump, pattern_search, entropy, bin_diff, resource_info, imphash, rich_header, overlay_detect, dwarf_info, xref, function_at, call_graph, follow_ptr, rtti_dump, struct_layout, vtable_scan, decompile, type_info, annotation_set, annotation_list, annotation_delete, annotation_batch, annotation_suggest"
	if op == "" {
		return errorResult("operation is required (" + allOps + ")")
	}
	if !validOperations[op] {
		return errorResult(fmt.Sprintf("unknown operation: %s (available: %s)", op, allOps))
	}
	if input.ResultOffset < 0 {
		return errorResult("result_offset must be non-negative")
	}
	if input.PDBForce && (input.PDBPath == "" || input.PDBPath == "none") {
		return errorResult("pdb_force needs pdb_path: name the PDB file to load despite a GUID mismatch (a PDB found automatically is never forced)")
	}
	if input.MaxOutputChars <= 0 {
		input.MaxOutputChars = defaultAnalyzeOutputChars
	}
	if input.MaxOutputChars > hardAnalyzeOutputChars {
		return errorResult(fmt.Sprintf("max_output_chars must be at most %d", hardAnalyzeOutputChars))
	}
	if op == "pe_info" {
		if input.MaxResults <= 0 {
			input.MaxResults = defaultPEImportResults
		}
		if input.MaxResults > hardPEImportResults {
			return errorResult(fmt.Sprintf("max_results for pe_info must be at most %d", hardPEImportResults))
		}
	}

	if input.FilePath == "" {
		input.FilePath = input.Path
	}
	if input.FilePath == "" {
		return errorResult("file_path is required")
	}
	resolvedPath, err := common.ResolveRequestPath(ctx, req, input.FilePath)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot resolve file_path: %v", err))
	}
	input.FilePath = resolvedPath
	if input.AnnotationsPath != "" {
		input.AnnotationsPath, err = common.ResolveRequestPath(ctx, req, input.AnnotationsPath)
		if err != nil {
			return errorResult(fmt.Sprintf("cannot resolve annotations_path: %v", err))
		}
	}
	if input.FilePathB != "" {
		input.FilePathB, err = common.ResolveRequestPath(ctx, req, input.FilePathB)
		if err != nil {
			return errorResult(fmt.Sprintf("cannot resolve file_path_b: %v", err))
		}
	}

	// Symlink check
	if !common.GetAllowSymlinks() {
		if lfi, err := os.Lstat(input.FilePath); err == nil && lfi.Mode()&os.ModeSymlink != 0 {
			return errorResult("symlinks are not allowed (see set_config allow_symlinks)")
		}
	}

	fi, err := os.Stat(input.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return errorResult(fmt.Sprintf("file not found: %s", input.FilePath))
		}
		return errorResult(fmt.Sprintf("cannot access file: %v", err))
	}
	if fi.IsDir() {
		return errorResult("path is a directory, not a file")
	}

	// No global file size check for analyze -- most operations (disassemble,
	// call_graph, xref, *_info) use lazy section-based reading and don't load
	// the entire file. Operations that do (strings, entropy, bin_diff) have
	// their own per-operation size checks. This allows analyzing multi-GB
	// binaries with debug symbols (common for game servers).

	if vaOperations[op] {
		if err := resolveSymbolArgs(&input); err != nil {
			return errorResult(err.Error())
		}
	}

	var result string
	switch op {
	case "disassemble":
		result, err = opDisassembleContext(ctx, input)
	case "instruction_search":
		result, err = opInstructionSearch(input)
	case "pe_info":
		result, err = opPEInfo(input)
	case "elf_info":
		result, err = opELFInfo(input)
	case "macho_info":
		result, err = opMachOInfo(input)
	case "strings":
		result, err = opStrings(input)
	case "hexdump":
		result, err = opHexdump(input)
	case "pattern_search":
		result, err = opPatternSearch(input)
	case "entropy":
		result, err = opEntropy(input)
	case "bin_diff":
		result, err = opBinDiff(input)
	case "resource_info":
		result, err = opResourceInfo(input)
	case "imphash":
		result, err = opImphash(input)
	case "rich_header":
		result, err = opRichHeader(input)
	case "overlay_detect":
		result, err = opOverlayDetect(input)
	case "dwarf_info":
		result, err = opDWARFInfo(input)
	case "xref":
		result, err = opXref(ctx, input)
	case "function_at":
		result, err = opFunctionAt(input)
	case "call_graph":
		result, err = opCallGraph(input)
	case "follow_ptr":
		result, err = opFollowPtr(input)
	case "rtti_dump":
		result, err = opRTTIDump(input)
	case "struct_layout":
		result, err = opStructLayout(input)
	case "vtable_scan":
		result, err = opVtableScan(input)
	case "decompile":
		result, err = opDecompile(ctx, input)
	case "type_info":
		result, err = opTypeInfo(input)
	case "annotation_batch":
		result, err = opAnnotationBatch(ctx, input)
	case "annotation_suggest":
		result, err = opAnnotationSuggest(ctx, input)
	case "annotation_set", "annotation_list", "annotation_delete":
		result, err = opAnnotations(ctx, input)
	}

	if err != nil {
		return errorResult(err.Error())
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, AnalyzeOutput{Result: result}, nil
}

// Register adds the analyze tool to the MCP server.
func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name:        "analyze",
		Description: `Static PE/ELF/Mach-O analysis: disassembly, semantic instruction search, headers, strings, hex/pattern search, entropy/diff, xrefs, functions/call graphs, pointers, RTTI, layouts, vtables, and decompilation to C (x86/x64 PE/ELF; va = hex address or symbol, comma-separated for several; a matching PDB or embedded DWARF is applied automatically, and the structs/enums the C names are printed after it), type_info for any other debug type (members with offsets, enum values). Use instruction_search for mnemonic/register/value queries and pattern_search for encoded bytes. Durable SQLite user labels/comments with revision-checked partial edits and bounded success receipts: annotation_set, annotation_list (query searches), annotation_delete; optional annotations_path selects the database for writes and rendered reads. disassemble/decompile show user notes separately from engine facts; decompile line_numbers=true supplies C-line/code_hash anchors (changed snapshots need review). PE annotations also accept rva. annotation_batch writes up to 32 notes with per-item receipts. evidence/provenance record user-supplied grounds. Decompile collects instruction notes from verified function ranges. annotation_suggest proposes C-line reattachment using stored anchor_text; never moves notes automatically. Annotation load errors are reported as warnings alongside analysis results. Prefer va for PE addresses. Use debug for runtime inspection.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, AnalyzeOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, AnalyzeOutput{Result: msg}, nil
}

func successResult(msg string) (*mcp.CallToolResult, AnalyzeOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, AnalyzeOutput{Result: msg}, nil
}
