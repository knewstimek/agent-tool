package help

// helpAnalyze is an indexed topic: a bare topic="analyze" request returns the
// intro plus the first line of every "## " section, so each section must open
// with a self-contained one-line summary. Keep sections to what changes the
// agent's next call (examples, parameters, how to read the output, what to try
// on failure). Engine internals are neither help nor README text.
func helpAnalyze() string {
	return `# analyze -- static binary analysis

Reads PE, ELF and Mach-O files without executing or modifying them.
  analyze(operation="<name>", file_path="/path/to/binary", ...)

Shared conventions:
- va takes a hex address ("0x140001000") or a symbol: export, import, PDB/DWARF
  function or global, name+0x10. Names match exactly, then by scope suffix
  (area or Rect::area for geo::Rect::area), then ignoring case. An overloaded
  name is an error listing each address; an unknown name lists similar ones.
- Addresses are virtual addresses of the image as linked: not file offsets and
  not live ASLR addresses. pe_info converts an RVA to a file offset.
- Long output stops at max_output_chars (default 32768, max 131072) and names
  the result_offset that continues it.
- strings, entropy and bin_diff load the whole file and are limited by
  max_file_size_mb (set_config, default 100); the other operations are not.
  Symlinks are rejected. For live process memory use memtool.

Typical order:
  1. pe_info / elf_info / macho_info -- sections, imports, W+X warnings
  2. entropy, overlay_detect -- packed/encrypted sections, appended payloads
  3. strings, pattern_search, then xref -- find data, then the code that uses it
  4. function_at, then decompile (C) or disassemble; type_info for types the C names
  5. call_graph, instruction_search -- callers/callees, constants reaching call arguments
  6. vtable_scan, rtti_dump, struct_layout, follow_ptr -- C++ classes and data
  7. annotation_set -- keep findings across sessions
  Also: imphash, rich_header, resource_info, dwarf_info, bin_diff

## decompile
Decompile functions to C (x86/x64 PE and ELF; Gosleigh, a Go port of Ghidra's decompiler).
  analyze(operation="decompile", file_path="/path/to/game.exe", va="0x140001000")
  analyze(operation="decompile", file_path="/path/to/libfoo.so", va="parse_header, 0x401230")

  Architecture, layout and calling convention come from the file (MSVC, gcc, Go ABI).
  Names, prototypes, struct/enum types, globals and locals come from debug info;
  the first source that applies wins:
    PDB (PE): found via the image's RSDS record, then beside the image, and used
      only when its GUID matches. pdb_path points elsewhere; pdb_path="none"
      disables it; pdb_force=true loads a mismatching PDB (relinked or patched
      image with the same code) and the output carries a warning.
    DWARF: embedded in ELF and MinGW/Go PE images.
    IL2CPP (Windows x64): il2cpp_signatures takes methodsigs.tsv, Il2CppDumper
      script.json or global-metadata.dat (v39 is read natively, other versions
      need an exported sidecar). Sidecars beside the binary and the standard
      Unity metadata locations are found automatically; pass the path when
      several metadata files exist or the image is stripped; "none" disables.
      It adds signatures and proven virtual-slot types, never names. A
      binary_sha256 header in the TSV must match the image. A sibling
      il2cpp-types.json supplies class layouts (docs/il2cpp-types.md).

  After each function come the definitions of the structs, unions and enums its
  C names (member offsets, bitfields, base classes, enum values), up to 6000
  characters and 32 members per type. For a type that was cut, or one reached
  only through a member (Point in n->pos[0].x):
    analyze(operation="type_info", file_path=..., type_name="Point, geo::Rect")

  Cost: the first call on a binary loads it (seconds for a large image with its
  PDB). Calls on the same file within 10 minutes reuse the loaded worker, so
  follow-up calls and paging are cheap. timeout_sec or the worker's 2 GB heap
  limit kills only the worker: finished functions are reported and the rest
  continue on a fresh worker.
  Server environment: AGENT_TOOL_ANALYZE_THREADS sets the scan threads
  (default NumCPU/4, between 2 and 4); AGENT_TOOL_NO_ANALYSIS_CACHE=1 disables
  the on-disk cache of whole-binary scans.
  Every function of a binary is a CLI job, not a tool call (minutes on a large
  program). Run it in the background and read the file:
    agent-tool decompile-all [-j workers] [-timeout sec] [-pdb path [-pdb-force]]
        [-il2cpp-signatures path|none] [-limit n] [-o out.jsonl] <binary>
  One JSON object per line: {"entry","name","c","secs"} or {"entry","error"};
  rerunning resumes an existing output file and retries its error entries, so
  rerun with a larger -timeout (default 30) for the ones that timed out.

  Reading the output:
    Imported functions print by name, delay-loaded ones included. An import by
      ordinal is named from the DLL beside the binary or in the Windows system
      directory; Ordinal_<n> means that DLL is not on this host.
    A va inside a function is moved to its start when x64 .pdata gives exact
      extents; otherwise a note asks you to confirm the start with function_at.
    halt_baddata(): that path ran into bytes that are no instruction; the rest
      of the function is still valid.
    "Function flow out of bounds: X flows to Y" + halt_missing(): obfuscated
      flow (junk bytes behind opaque predicates) was cut at the function's
      x64 .pdata extent; the rest prints.
    "Flow exceeded maximum allowable instructions": the same cause without a
      .pdata extent to cut at (x86, leaf functions); nothing prints.
    For both, fix the branch directions a runtime trace or disassembly
    established and retry:
      analyze(operation="decompile", file_path=..., va="0x140012340",
              assume_branches="0x140012375=taken,0x1400123a2=fallthrough")
    Each listed conditional jump is treated as jmp / nop: the other side is not
    decompiled, the C marks each one, and addresses no decompiled flow reached
    are listed.
    Output ending right after a call that should return, with a warning naming
      the callee: it was judged non-returning from its call sites.
      noreturn_verify=true keeps callees whose code reaches a ret returning.

  Parameters:
    va: function entry, hex or symbol (PDB names are qualified:
        Player::TakeDamage); up to 16, comma-separated
    pdb_path, pdb_force, il2cpp_signatures (alias il2cpp_script): see above
    timeout_sec: worker time limit (default 60, max 600)
    assume_branches: <hex address>=taken|fallthrough, comma-separated (max 256)
    noreturn_verify: keep voted non-returning callees whose code reaches a ret returning
    line_numbers: print C-body L numbers and code_hash (for annotation_set)
    annotations_path: notes database to render (see annotation_set)
    max_output_chars / result_offset: output cap and continuation

## type_info
Print struct/class/union/enum definitions by name from the PDB or DWARF.
  analyze(operation="type_info", file_path="/path/to/game.exe", type_name="Player, EState")

  Structs, classes and unions list every member with its offset (+0x10 int w_;),
  bitfield bit ranges, base classes (super_Base) and union alternatives; enums
  list each value in hex and decimal. Names match qualified (geo::Rect), as
  decompile prints them (Rect), or ignoring case. A short name shared by several
  namespaces prints each; an unknown one lists similar names. Tagless C structs
  (typedef struct {...} Obj) are found by the typedef name.

  Parameters:
    type_name: up to 16 names, comma-separated (required)
    pdb_path / pdb_force: as for decompile
    max_output_chars / result_offset: output cap and continuation

## disassemble
Disassemble x86 (16/32/64-bit) or ARM (32/64-bit) code at a virtual address or file offset.
  analyze(operation="disassemble", file_path="/path/to/app.exe", va="0x140001000")
  analyze(operation="disassemble", file_path="/path/to/arm_binary",
          offset=0, count=50, mode=64, arch="arm")

  Prefer va: the file offset, base address and mode come from the headers, and
  decoding stops at the function's end when .pdata gives it, so it never runs
  into the next function. With offset you set mode/arch/base_addr yourself.

  Output: address: instruction  [; import/export symbol] [; user note]
  x86 uses Intel syntax. Bytes that do not decode print as "db 0xNN" / ".word"
  and are skipped. A switch table the compiler placed inside the code prints as
  one "; switch table, N x 4-byte entries" line with its case targets. When the
  instruction cap is hit, a truncation note names the va to resume from.

  Parameters:
    va: start address, hex or symbol
    offset: file offset to start from when va is not used (default 0)
    count: instructions to decode (default 50, max 1000)
    stop_at_ret: stop at the function's return (RET + padding or a new prologue)
    show_bytes: add the hex encoding column (default false)
    arch: x86 (default) or arm; mode: x86 16/32/64, arm 32/64 (default 64)
    base_addr: address shown for file offset 0 (hex, default 0); displayed
               address = base_addr + offset + position. Only with offset.
    annotations_path: notes database to render (see annotation_set)
    max_output_chars / result_offset: output cap and continuation

## function_at
Find the function containing an address (PE), with a confidence for its start, and disassemble it.
  analyze(operation="function_at", file_path="/path/to/binary.exe", va="0x140001000")

  The best available source decides the start: a matching PDB (exact, also for
  x86), x64 .pdata, for x64 leaf functions (no unwind data) the code layout,
  the export table plus direct-call targets and vtable/callback pointers
  discovered from it, and last a prologue/epilogue pattern scan for code no
  export reaches.

  READ these before trusting the result:
    start_source: pdb | pdata | layout | export | call-target | prologue | heuristic | heuristic-misaligned
    confidence:   exact (PDB / .pdata / named export) | high (direct-call target, x64 leaf from layout)
                | medium (strong prologue) | low (weak/uncertain)
  "exact" and "high" are trustworthy, "medium" is a good guess, "low" is not
  authoritative. "low" with start_source "heuristic-misaligned" means the start
  points INTO an instruction: do NOT build on it. Call function_at on a nearby
  export instead, or disassemble backward to find the real prologue.

  Parameters:
    va: address inside the function, hex or symbol (required)
    count: instructions to disassemble (default 50, max 200)
    pdb_path / pdb_force: as for decompile

## xref
Find the code and data that reference an address, a range, the strings containing a text, or a struct field (PE/ELF/Mach-O).
  analyze(operation="xref", file_path="/path/to/binary", target_va="0x140001000")
  analyze(operation="xref", file_path="/path/to/binary",
          target_va="0x140020000", target_end_va="0x140020fff")
  analyze(operation="xref", file_path="/path/to/binary", target_text="Login failed")
  analyze(operation="xref", file_path="/path/to/binary", field="Player::health")

  Every reference names the function it sits in ("; in World::Tick+0x42") and
  the summary counts the referencing functions.
  Reference kinds:
    Code: CALL/JMP/Jcc, RIP-relative and absolute operands, immediates (ARM64
      BL/B/ADRP pairs, ARM32 BL/B). A lea/mov of the target followed by call/jmp
      through that register is reported as a CALL ("then call rax").
    DATA: x64 MSVC tables and arrays read through the image base. A switch case
      block reports the dispatch jump that leads to it (JMP, "switch case N").
    PTR: pointers stored in data sections -- vtable slots (with the slot index),
      function-pointer and callback tables.

  target_text finds up to 16 stored strings (UTF-8/ASCII and UTF-16LE)
    containing the text and lists the references to each; max_results is shared.
  field is Class::member (Go: pkg.Type::field), the class as decompile prints it
    or qualified; the offset comes from the PDB/DWARF, inherited members
    included. Functions using that offset are decompiled: those whose C names
    the member are confirmed accesses (with the lines), the rest only share the
    offset. Here max_results = functions to decompile (default 32, max 128) and
    timeout_sec bounds the whole call (default 120).

  Parameters:
    target_va / target_end_va: address (hex or symbol) or inclusive range
    target_text: text to find in stored strings (instead of target_va)
    field: Class::member (instead of target_va)
    max_results: references (default 200, max 1000); for field, functions
    pdb_path / pdb_force: as for decompile

## call_graph
Static call graph around a root function: callers, data references and a callee tree (PE/ELF/Mach-O; x86/x64/ARM64/ARM32).
  analyze(operation="call_graph", file_path="/path/to/binary", va="0x140001000")

  Output:
    Callers: functions that call the root (1 level). Tail jumps are marked;
      callers of a thunk that only jumps to the root are listed "via thunk".
    Referenced from data: vtable slots and pointer tables holding the root, for
      functions only called indirectly.
    Callees: tree to the requested depth; revisited nodes print "(already shown)".
    Not shown: direct calls to addresses that are no known function start (junk
      bytes behind opaque predicates).

  Reliability: each function's calls are collected by following its control
  flow, not a linear scan, so a boundary error cannot leak a neighbour's calls
  in. x64 PE with .pdata has exact function ranges. x86 PE, ELF and Mach-O take
  function starts from exports/symbols, call targets and the code layout, so
  obfuscated x86 code can still list junk calls.

  Parameters:
    va: root function, hex or symbol (required)
    count: callee depth (default 2, max 5)
    max_results: nodes to visit (default 200, max 500)

## instruction_search
Find x86/x64 instructions by mnemonic, register, immediate or memory displacement, and trace a constant into call arguments.
  analyze(operation="instruction_search", file_path="/path/to/module.dll",
          mnemonic="MOV", register="R9D", immediate="0x327")
  analyze(operation="instruction_search", file_path="/path/to/module.dll",
          immediate="0x327", call_target="DeviceApi")   # calls receiving 0x327
  analyze(operation="instruction_search", file_path="/path/to/module.dll",
          displacement="0x410")                         # who reads/writes [reg+0x410]
  analyze(operation="instruction_search", file_path="/path/to/module.dll",
          register="RSP", displacement="0xf8")          # stack bases only when named

  No byte encoding is needed. Every hit names its function
  ("; in Class::Method+0x41") and is labelled:
    confirmed: an instruction start reached by control flow from a function start
    candidate: decodes validly but was not reached -- may be data or a misaligned decode

  Value tracing (trace_values, on by default when immediate is set) follows the
  value inside each function through registers, stack slots, read-only
  constants, arithmetic and switch cases, and reports the CALL / tail-call
  arguments it reaches; import calls print as dll!Function. A traced result is
  "confirmed" when it holds on every path and loop iteration, "possible" when on
  some. Unknown memory aliases and values returned by other functions are not
  guessed. x86 argument cleanup (ret N) of imports is read from the 32-bit DLL
  beside the binary or in SysWOW64; without it stale arguments of earlier calls
  can appear.
  trace_scope=seeded (default) traces only functions that hold the value;
  trace_scope=all also finds values computed from other constants (40*25, loop
  counters) and is several times slower. Repeat searches on the same file are
  served from a cache.

  Parameters:
    mnemonic: MOV, ADD, CALL, ... (case-insensitive)
    register: explicit GPR operand such as R9D, EAX or RCX; with displacement it
              matches the base/index of that memory operand
    immediate: hex or decimal value such as 0x327 or 807
    displacement: memory displacement such as 0x410, matching [reg+0x410]
                  (stack-pointer and RIP-relative bases excluded unless named)
    call_target: case-insensitive target symbol/address substring; needs
                 immediate, and defaults findings to call
    findings: all (default), call, or producer
    trace_values: default true when immediate is supplied
    trace_scope: seeded (default) or all
    max_output_chars: page budget (default 32768, minimum 256)
    result_offset: next row index printed by the previous page. Keep the filters and view unchanged.
    max_results: optional per-page row limit (max 1000)
    group_by_function: one row per function with its address and direct/trace counts
  The result reports total matches and rows shown. Partial analysis marks traces that may be incomplete.

## pe_info
Parse PE headers (EXE/DLL): sections, imports with IAT slot VAs, exports and an RVA-to-file-offset table.
  analyze(operation="pe_info", file_path="/path/to/file.dll")
  analyze(operation="pe_info", file_path="/path/to/file.dll", section=".pdata")

  Also prints machine type, image base and entry point. Writable+executable
  sections are flagged. The import list pages with result_offset + max_results
  (default 500, max 100000); IAT slot VAs feed xref. Delay-loaded imports are
  listed with their slots too (30 per DLL); any import name works as xref
  target_va.

  Parameters:
    section: show one section. ".pdata" lists every RUNTIME_FUNCTION (start VA,
             end VA, size, unwind RVA); ".text" disassembles from the entry point
    rva: convert an RVA to a file offset (hex, e.g. "0x36A20")

## elf_info
Parse ELF headers: sections, program headers, imported libraries/symbols and dynamic exports.
  analyze(operation="elf_info", file_path="/path/to/binary")

  Also prints class, OS/ABI, type, machine and entry point. Writable+executable
  sections and segments are flagged.

  Parameters:
    section: show one section

## macho_info
Parse Mach-O binaries: load commands, segments, sections and imports (every architecture of a universal binary).
  analyze(operation="macho_info", file_path="/path/to/binary")

  Also prints CPU type, binary type and flags (PIE, DYLDLINK, ...). Segments
  show MaxProt/InitProt; writable+executable ones are flagged.

  Parameters:
    section: show one section

## strings
Extract printable strings with their file offsets (and VAs for PE).
  analyze(operation="strings", file_path="/path/to/binary", min_length=6, max_results=100)

  Output: offset (VA): "string". Pass the text to xref target_text to find the
  code that uses it.

  Parameters:
    min_length: minimum string length (default 4)
    max_results: default 500, max 2000
    encoding: ascii (default, bytes 0x20-0x7E) or utf8 (multi-byte aware)

## hexdump
Dump raw bytes as hex + ASCII, 16 per line.
  analyze(operation="hexdump", file_path="/path/to/binary", offset=8192, length=512)

  Parameters:
    offset: file offset to start from (default 0)
    va: start address (hex or symbol) instead of offset
    length: bytes to dump (default 256, max 4096)

## pattern_search
Search for a hex byte pattern with ?? wildcards.
  analyze(operation="pattern_search", file_path="/path/to/binary", pattern="48 89 5C 24 ??")

  Bytes are space-separated hex; "??" matches any byte (the example matches
  mov [rsp+??], rbx). Results give the file offset, plus the VA for PE. Reads in
  chunks, so multi-GB files work.

  Parameters:
    pattern: hex byte pattern (required)
    max_results: default 100, max 500

## entropy
Shannon entropy of the file and of each section, to spot packed or encrypted regions.
  analyze(operation="entropy", file_path="/path/to/binary")

  Scale is 0-8 bits/byte: above 7 is compressed, encrypted or random; 5-7 is
  compiled code; 3-5 is text or simple code; below 3 is headers, tables or
  padding. A section above 7 in an otherwise normal binary suggests packing.
  Section boundaries come from PE/ELF/Mach-O headers; other files are measured
  in 4 KB blocks.

## overlay_detect
Check for data appended after the last section (PE/ELF/Mach-O).
  analyze(operation="overlay_detect", file_path="/path/to/file.exe")

  Reports the overlay's size and share of the file, a hex preview and what it
  looks like (ZIP, GZIP, RAR, 7z, embedded PE/ELF/Mach-O). Typical of packers,
  droppers and self-extracting archives.

## struct_layout
Lay a debug type over image memory (PE) member by member with values, or dump annotated pointer-sized slots.
  analyze(operation="struct_layout", file_path="/path/to/game.exe", va="g_world")
  analyze(operation="struct_layout", file_path="/path/to/game.exe", va="0x140050000", type_name="Player")

  With debug types (PDB, or MinGW DWARF): the global starting at va, or
  type_name laid over va, prints nested structures as dotted paths, bitfields
  extracted, enums named, pointers annotated, char arrays as strings and
  zero-filled aggregates as {0}. A va inside a global gets a note naming its
  start. Values are the image's initial data (.bss reads as zero), not a running
  process.
  Without a type: pointer-sized slots, each annotated with a symbol name,
  [code]/[data]/[rdata] or [null] -- for vtables and untyped data.

  Parameters:
    va: start address, hex or symbol (required)
    type_name: type to lay over va (default: the global at va)
    length: bytes to dump (default 64, max 512)
    pdb_path / pdb_force: as for decompile

## follow_ptr
Follow a chain of pointers in a PE image, naming the symbol or section at each step.
  analyze(operation="follow_ptr", file_path="/path/to/binary.exe", va="0x140050000", count=6)

  Output: [0] 0x140050000 (.rdata) -> 0x140060ABC (MyClass::vtable)
  Stops on null, an unmapped address, the depth limit or a revisited address.

  Parameters:
    va: start address, hex or symbol (required)
    count: maximum depth (default 4, max 10)

## rtti_dump
Read the MSVC RTTI of one vtable: class name and base classes (PE, x86/x64).
  analyze(operation="rtti_dump", file_path="/path/to/binary.exe", va="0x140050000")

  Prints the mangled and demangled class name (std::bad_exception) and the base
  class list with displacements. Get vtable addresses from vtable_scan.

  Parameters:
    va: vtable address, hex or symbol (required)

## vtable_scan
List every MSVC vtable with RTTI in a PE's .rdata, with demangled class names.
  analyze(operation="vtable_scan", file_path="/path/to/binary.exe")

  No parameters. Use it to map the classes of a binary, then rtti_dump a vtable
  for its hierarchy and struct_layout/xref to see its slots and users.

## annotation_set / annotation_list / annotation_delete
Save, list and delete your own labels/comments on instructions, functions and decompiled C lines (separate SQLite DB).
  analyze(operation="annotation_set", file_path="/path/to/sample.exe", rva="0x1234",
          subject="rax", comment="User pointer returned here")
  analyze(operation="annotation_list", file_path="/path/to/sample.exe", query="User")
  analyze(operation="annotation_delete", file_path="/path/to/sample.exe",
          annotation_id="<id from set/list>", expected_revision="<revision>")

  Saved notes print inside disassemble and decompile output with their status,
  ID and revision (at most 500 per output; annotation_list reads the rest).
  They are your assertions: the engine renames, retypes and verifies nothing.

  Database: pass the SAME annotations_path to every annotation operation and to
  the disassemble/decompile calls that should show the notes. Omitted, it is
  <user config dir>/agent-tool/analysis-annotations.sqlite. Reads never create
  it. Records are scoped by the binary's SHA-256: a moved or copied file keeps
  its notes, a modified build does not inherit them. Keep private notes outside
  tracked/public files.

  Fields:
    annotation_kind: instruction (default), function (entry VA) or decompile (C line)
    va (hex or symbol) or rva (PE, module-relative): the anchor
    subject: register/operand/variable the note is about, at this anchor only
    label / comment: at least one required (max 256 / 8192 UTF-8 bytes)
    annotation_status: hypothesis (default), confirmed or rejected
    evidence: up to 16 of {kind: static|runtime|user, detail (required), va, source}
    provenance: where the judgment came from (max 512 bytes)

  C-line note: decompile with line_numbers=true, then pass its L number and code_hash:
    analyze(operation="annotation_set", file_path=..., va="handler",
            annotation_kind="decompile", line=3, code_hash="<64 hex chars>",
            anchor_text="<that raw C line>", comment="Checks user flags")
  When the C later changes (new PDB or decompiler result) the note is not moved
  to another line: it shows as needs_review at the function header until you
  re-anchor it with annotation_suggest, which needs anchor_text.

  Update and delete take annotation_id + expected_revision from set/list. A
  stale revision is a conflict and never overwrites: list again, then retry.
  Set without an ID creates a note; an occupied anchor is rejected.
  An update keeps omitted fields. To clear a field or move the anchor use
  annotation_patch (label, comment, subject, annotation_status, annotation_kind,
  va, rva, line, code_hash, evidence, provenance, anchor_text; "" / [] / line=0
  clear; patch values override top-level ones):
    analyze(operation="annotation_set", file_path=..., annotation_id="<id>",
            expected_revision="1", annotation_patch={"comment":"Confirmed","label":""})

  List filters: annotation_id, va/rva, annotation_kind, subject,
  annotation_status, query (literal substring of label, comment, subject,
  provenance or evidence; ASCII case folding). max_results defaults to 50
  (max 200); continue with result_offset = next_result_offset.
  A committed write is never reported as failed because of max_output_chars: it
  returns a short receipt (saved=true, annotation_id, revision, details_omitted=true).

## annotation_batch / annotation_suggest
Apply up to 32 annotation set/delete items in one call; suggest where a C-line note belongs after the C changed.
  analyze(operation="annotation_batch", file_path="/path/to/sample.exe",
          batch=[{"operation":"set","rva":"0x1234","comment":"User pointer",
                  "provenance":"manual analysis",
                  "evidence":[{"kind":"static","va":"0x140001230",
                               "detail":"Return used as context"}]},
                 {"operation":"delete","annotation_id":"<id>","expected_revision":"1"}])
  Items take the annotation_set / annotation_delete fields; file_path and
  annotations_path are per call, not per item. NOT a transaction: each item
  commits on its own and gets an indexed success/revision/conflict receipt, so
  read every receipt. On cancellation completed items stay saved and the rest
  are marked failed. max_output_chars must be at least 768*items+256 (the
  default covers 32).

  analyze(operation="annotation_suggest", file_path="/path/to/sample.exe",
          annotation_id="<C-note ID>")
  Read-only. Returns the current code_hash, expected_revision,
  requires_confirmation and up to 3 candidates (line, anchor_text, score,
  reason) in the same function. Equal top scores are ambiguous, and a note saved
  without anchor_text cannot be matched: choose the line yourself. The note is
  never moved for you; apply the choice with
    analyze(operation="annotation_set", file_path=..., annotation_id="<id>",
            expected_revision="<from suggest>",
            annotation_patch={"line":N,"code_hash":"<current hash>","anchor_text":"<raw C line>"})

## imphash
Compute the PE import hash (MD5 of the normalized import table) for classification.
  analyze(operation="imphash", file_path="/path/to/file.exe")

  Binaries built from the same source share an imphash (the VirusTotal/MISP
  convention). Prints the hash and the first 20 normalized imports (dll.function).

## rich_header
Parse the PE Rich header: which compiler/linker/assembler versions built the object files.
  analyze(operation="rich_header", file_path="/path/to/file.exe")

  Useful for attribution and build-environment identification; includes the
  Rich header MD5 for clustering.

## resource_info
List PE resources and version information.
  analyze(operation="resource_info", file_path="/path/to/file.exe")

  Resource type counts (RT_ICON, RT_VERSION, RT_MANIFEST, ...), entries with
  type, ID, language and size, and the version strings (CompanyName,
  ProductName, FileVersion, ...).

## dwarf_info
Summarize DWARF debug info (PE/ELF/Mach-O): compilation units and functions with address ranges.
  analyze(operation="dwarf_info", file_path="/path/to/binary")

  Also counts variables/parameters and types. "Binary appears stripped" means
  there is no DWARF; decompile and type_info use DWARF automatically when present.

## bin_diff
Compare two files byte by byte and list the differing offsets.
  analyze(operation="bin_diff", file_path="/path/to/file_a", file_path_b="/path/to/file_b")

  Reports both sizes, each difference (offset, byte in A, byte in B) and the
  total count -- for finding patched bytes or comparing versions.

  Parameters:
    file_path_b: second file (required)
    max_results: differences to show (default 100, max 500)`
}
