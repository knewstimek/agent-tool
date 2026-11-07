package analyze

import (
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"

	"agent-tool/common"

	"golang.org/x/arch/arm/armasm"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

const (
	defaultDisasmCount = 50
	maxDisasmCount     = 1000
)

// opDisassemble disassembles machine code from a binary file.
// Supports x86 (16/32/64-bit) and ARM (32/64-bit).
// Reads only the needed portion instead of the entire file to save memory.
func opDisassemble(input AnalyzeInput) (string, error) {
	return opDisassembleContext(context.Background(), input)
}

func opDisassembleContext(ctx context.Context, input AnalyzeInput) (string, error) {
	// VA-to-offset: try PE, then ELF, then Mach-O for VA resolution.
	// Also auto-detects arch/mode and provides symbol map for annotations.
	var funcEndFileOff int64 = -1   // function boundary from .pdata or heuristic
	var symbolMap map[uint64]string // VA -> symbol name for inline annotations
	var resolved *disasmResolved
	if input.VA != "" {
		var err error
		resolved, err = disasmResolveVA(input.FilePath, input.VA)
		if err != nil {
			return "", err
		}
		if resolved.closer != nil {
			defer resolved.closer()
		}

		input.Offset = int(resolved.fileOffset)
		if input.BaseAddr == "" {
			input.BaseAddr = fmt.Sprintf("0x%x", resolved.displayBase)
		}
		if input.Arch == "" && resolved.arch != "" {
			input.Arch = resolved.arch
		}
		if input.Mode == 0 && resolved.mode != 0 {
			input.Mode = resolved.mode
		}
		funcEndFileOff = resolved.funcEndFileOff
		symbolMap = resolved.symbols
	}

	fi, err := os.Stat(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot access file: %w", err)
	}
	fileSize := fi.Size()

	offset := input.Offset
	if offset < 0 || int64(offset) >= fileSize {
		return "", fmt.Errorf("offset %d out of range (file size: %d)", offset, fileSize)
	}

	count := input.Count
	if count <= 0 {
		count = defaultDisasmCount
	}
	if count > maxDisasmCount {
		count = maxDisasmCount
	}

	mode := input.Mode
	if mode == 0 {
		mode = 64
	}

	arch := strings.ToLower(strings.TrimSpace(input.Arch))
	if arch == "" {
		arch = "x86"
	}

	switch arch {
	case "x86":
		if mode != 16 && mode != 32 && mode != 64 {
			return "", fmt.Errorf("invalid mode for x86: %d (must be 16, 32, or 64)", mode)
		}
	case "arm":
		if mode != 32 && mode != 64 {
			return "", fmt.Errorf("invalid mode for arm: %d (must be 32 or 64)", mode)
		}
	default:
		return "", fmt.Errorf("unsupported arch: %s (available: x86, arm)", arch)
	}

	// Determine read size based on architecture
	// x86: up to 15 bytes per instruction, ARM: fixed 4 bytes per instruction
	var maxInstLen int64
	if arch == "arm" {
		maxInstLen = 4
	} else {
		maxInstLen = 15
	}
	readSize := int64(count) * maxInstLen
	if int64(offset)+readSize > fileSize {
		readSize = fileSize - int64(offset)
	}
	// Clamp read to function boundary from .pdata (prevents disassembly past function end)
	clamped := false
	if funcEndFileOff > 0 && int64(offset) < funcEndFileOff {
		funcReadSize := funcEndFileOff - int64(offset)
		if funcReadSize < readSize {
			readSize = funcReadSize
			clamped = true
		}
	}

	f, err := os.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("cannot open file: %w", err)
	}
	defer f.Close()
	data := make([]byte, readSize)
	// ReadAt returns io.EOF when fewer bytes are available than requested
	// (e.g. near end of file). Partial data is still valid, so ignore EOF.
	if _, err := f.ReadAt(data, int64(offset)); err != nil && err.Error() != "EOF" {
		return "", fmt.Errorf("cannot read file: %w", err)
	}

	// Parse base address for display
	var baseAddr uint64
	if input.BaseAddr != "" {
		ba := strings.TrimPrefix(input.BaseAddr, "0x")
		ba = strings.TrimPrefix(ba, "0X")
		baseAddr, err = strconv.ParseUint(ba, 16, 64)
		if err != nil {
			return "", fmt.Errorf("invalid base_addr: %s", input.BaseAddr)
		}
	}

	var text string
	reachedEnd := false
	showBytes := common.FlexBool(input.ShowBytes)
	switch arch {
	case "arm":
		if mode == 64 {
			text, err = disasmARM64(data, baseAddr, offset, count, showBytes)
		} else {
			text, err = disasmARM32(data, baseAddr, offset, count, showBytes)
		}
	default:
		text, reachedEnd, err = disasmX86Run(data, baseAddr, offset, count, mode,
			disasmOpts{symbols: symbolMap, stopAtRet: common.FlexBool(input.StopAtRet), showBytes: showBytes})
	}
	if err != nil {
		return "", err
	}
	// Without this note the output just ends at the clamp, indistinguishable
	// from a complete function, while MSVC hot/cold splitting puts the rest of
	// the function in other .pdata ranges and a heuristic end may be a guess.
	if clamped && reachedEnd && resolved != nil && resolved.endNote != nil {
		text += resolved.endNote(baseAddr + uint64(funcEndFileOff))
	}
	return renderDisassemblyAnnotations(ctx, input, text)
}

// DisasmBytes disassembles raw machine code bytes.
// Exported for use by other packages (e.g., memtool for live process memory).
func DisasmBytes(data []byte, baseAddr uint64, arch string, mode int, count int, showBytes bool) (string, error) {
	if count <= 0 {
		count = defaultDisasmCount
	}
	if count > maxDisasmCount {
		count = maxDisasmCount
	}
	if arch == "" {
		arch = "x86"
	}
	switch arch {
	case "arm":
		if mode == 64 {
			return disasmARM64(data, baseAddr, 0, count, showBytes)
		}
		return disasmARM32(data, baseAddr, 0, count, showBytes)
	default:
		if mode == 0 {
			mode = 64
		}
		text, _, err := disasmX86Run(data, baseAddr, 0, count, mode, disasmOpts{showBytes: showBytes, memory: true})
		return text, err
	}
}

// disasmOpts are the x86 listing's options. symbols names call/jump targets;
// stopAtRet stops after a RET/RETF followed by INT3/NOP padding or a new
// function prologue (a confirmed function boundary); showBytes adds each
// instruction's encoding as a hex column. memory marks a listing of live
// process memory (memtool disasm), whose resume parameter is address=, with
// no file offset or stop_at_ret.
type disasmOpts struct {
	symbols   map[uint64]string
	stopAtRet bool
	showBytes bool
	memory    bool
}

// disasmLine writes one listing line: address, optional hex encoding, text.
func disasmLine(sb *strings.Builder, addr uint64, raw []byte, text string, showBytes bool) {
	if !showBytes {
		fmt.Fprintf(sb, "0x%x:  %s\n", addr, text)
		return
	}
	hex := make([]byte, 0, 3*len(raw))
	for i, b := range raw {
		if i > 0 {
			hex = append(hex, ' ')
		}
		hex = fmt.Appendf(hex, "%02x", b)
	}
	fmt.Fprintf(sb, "0x%x:  %-30s %s\n", addr, hex, text)
}

// disasmX86Run is the x86 linear-sweep listing. It also reports whether every
// byte of data was consumed (neither the instruction cap nor stop_at_ret
// ended it first).
//
// A switch table placed inside the code (MSVC x64 puts it right after the
// function's instructions) is not code: once an indirect jmp resolves to a
// table ahead in the window, the sweep prints the table as one data line
// with its case targets and skips it, instead of decoding the entries as
// garbage instructions that also desynchronize the code after them.
func disasmX86Run(data []byte, baseAddr uint64, offset, count, mode int, opts disasmOpts) (string, bool, error) {
	var sb strings.Builder
	pos := 0
	decoded := 0
	stoppedAtRet := false
	winVA := baseAddr + uint64(offset)
	inWindow := func(va uint64) bool { return va >= winVA && va-winVA < uint64(len(data)) }
	read := func(va uint64, n int) []byte {
		if !inWindow(va) || va-winVA+uint64(n) > uint64(len(data)) {
			return nil
		}
		return data[va-winVA : va-winVA+uint64(n)]
	}
	// Data tables ahead in the window: position -> (size, listing text).
	type dataTable struct {
		size int
		text string
	}
	tables := map[int]dataTable{}
	addTable := func(va uint64, size int, text string) {
		if tp := int(va - winVA); inWindow(va) && va-winVA > uint64(pos) && tp+size <= len(data) {
			tables[tp] = dataTable{size, text}
		}
	}

	for decoded < count && pos < len(data) {
		if tb, ok := tables[pos]; ok {
			disasmLine(&sb, winVA+uint64(pos), nil, tb.text, false)
			pos += tb.size
			decoded++
			continue
		}
		inst, err := x86asm.Decode(data[pos:], mode)
		addr := winVA + uint64(pos)
		if err != nil {
			// Failed to decode -- emit raw byte and skip
			disasmLine(&sb, addr, data[pos:pos+1], fmt.Sprintf("db 0x%02x", data[pos]), opts.showBytes)
			pos++
			decoded++
			continue
		}

		instBytes := data[pos : pos+inst.Len]

		// Intel syntax with address context for RIP-relative resolution
		asmStr := x86asm.IntelSyntax(inst, addr, nil)

		// Symbol annotation: resolve target addresses to import/export names
		if annotation := resolveSymbol(inst, addr, opts.symbols, mode); annotation != "" {
			asmStr += "  ; " + annotation
		}
		disasmLine(&sb, addr, instBytes, asmStr, opts.showBytes)

		if inst.Op == x86asm.JMP {
			if _, rel := inst.Args[0].(x86asm.Rel); !rel {
				if sw := switchTable(data, winVA, pos, inst, mode, read, inWindow); len(sw.cases) > 0 {
					parts := make([]string, len(sw.cases))
					for i, c := range sw.cases {
						parts[i] = fmt.Sprintf("0x%x", c)
					}
					addTable(sw.table, 4*len(sw.cases), fmt.Sprintf("; switch table, %d x 4-byte entries (data, not code) -> %s",
						len(sw.cases), strings.Join(parts, ", ")))
					if sw.index != 0 {
						idx := make([]string, sw.indexLen)
						for i, b := range read(sw.index, sw.indexLen) {
							idx[i] = strconv.Itoa(int(b))
						}
						addTable(sw.index, sw.indexLen, fmt.Sprintf("; switch index table, %d bytes (data, not code): case value -> entry %s",
							sw.indexLen, strings.Join(idx, ",")))
					}
				}
			}
		}

		pos += inst.Len
		decoded++

		// stop_at_ret: check if this instruction is a RET/RETF and next bytes
		// indicate a function boundary (padding or new prologue)
		if opts.stopAtRet && isRetInstruction(instBytes) {
			if pos >= len(data) || isFuncBoundaryAfterRet(data, pos, mode) {
				stoppedAtRet = true
				break
			}
		}
	}

	suffix := fmt.Sprintf("\n(%d instructions from offset 0x%x, arch=x86, mode=%d", decoded, offset, mode)
	if opts.memory {
		suffix = fmt.Sprintf("\n(%d instructions, arch=x86, mode=%d", decoded, mode)
	}
	if stoppedAtRet {
		suffix += ", stopped at function return"
	}
	suffix += ")"
	sb.WriteString(suffix)
	// Truncation hint: hitting the instruction cap (not a ret/boundary) with data
	// still ahead means this is a large function cut mid-way. Tell the agent where
	// to resume so it paginates instead of assuming it saw the whole function.
	if decoded >= count && !stoppedAtRet && pos < len(data) {
		nextVA := baseAddr + uint64(offset) + uint64(pos)
		if opts.memory {
			fmt.Fprintf(&sb, "\n** truncated at the %d-instruction cap (NOT a function end). "+
				"To continue, disasm with address=\"0x%x\", optionally with a larger count. **", count, nextVA)
		} else {
			fmt.Fprintf(&sb, "\n** truncated at the %d-instruction cap (NOT a function end). "+
				"To continue, disassemble with va=\"0x%x\" (or offset=%d), optionally with a larger count or stop_at_ret=true. **",
				count, nextVA, offset+pos)
		}
	}
	return sb.String(), !stoppedAtRet && pos >= len(data), nil
}

// isRetInstruction checks if the instruction bytes are a RET variant.
// Handles: RET (C3), RET imm16 (C2), RETF (CB), RETF imm16 (CA),
// and prefixed forms: BND RET (F2 C3), REP RET (F3 C3).
func isRetInstruction(instBytes []byte) bool {
	if len(instBytes) == 0 {
		return false
	}
	op := instBytes[0]
	// Skip BND (F2) or REP (F3) prefix -- compilers emit "bnd ret" or "rep ret"
	if (op == 0xF2 || op == 0xF3) && len(instBytes) >= 2 {
		op = instBytes[1]
	}
	switch op {
	case 0xC3, 0xCB: // RET, RETF
		return true
	case 0xC2, 0xCA: // RET imm16, RETF imm16
		return true
	}
	return false
}

// isFuncBoundaryAfterRet checks if the bytes after a RET indicate a function boundary:
// - INT3 (0xCC) or NOP (0x90) padding
// - A known function prologue pattern
func isFuncBoundaryAfterRet(data []byte, pos, mode int) bool {
	if pos >= len(data) {
		return true // end of data = boundary
	}
	next := data[pos]
	// INT3 or NOP padding after RET = definite function boundary
	if next == 0xCC || next == 0x90 {
		return true
	}
	// New function prologue after RET = definite function boundary
	if matchesPrologue(data, pos, mode) {
		return true
	}
	return false
}

func disasmARM64(data []byte, baseAddr uint64, offset, count int, showBytes bool) (string, error) {
	var sb strings.Builder
	decoded := 0

	// ARM64 instructions are fixed 4 bytes
	for pos := 0; decoded < count && pos+4 <= len(data); pos += 4 {
		addr := baseAddr + uint64(offset) + uint64(pos)

		inst, err := arm64asm.Decode(data[pos : pos+4])
		text := fmt.Sprintf(".word 0x%08x", binary.LittleEndian.Uint32(data[pos:]))
		if err == nil {
			text = inst.String()
		}
		disasmLine(&sb, addr, data[pos:pos+4], text, showBytes)
		decoded++
	}

	sb.WriteString(fmt.Sprintf("\n(%d instructions from offset 0x%x, arch=arm, mode=64)", decoded, offset))
	return sb.String(), nil
}

func disasmARM32(data []byte, baseAddr uint64, offset, count int, showBytes bool) (string, error) {
	var sb strings.Builder
	decoded := 0

	// ARM32 instructions are fixed 4 bytes (ARM mode, not Thumb)
	for pos := 0; decoded < count && pos+4 <= len(data); pos += 4 {
		addr := baseAddr + uint64(offset) + uint64(pos)

		inst, err := armasm.Decode(data[pos:pos+4], armasm.ModeARM)
		text := fmt.Sprintf(".word 0x%08x", binary.LittleEndian.Uint32(data[pos:]))
		if err == nil {
			text = inst.String()
		}
		disasmLine(&sb, addr, data[pos:pos+4], text, showBytes)
		decoded++
	}

	sb.WriteString(fmt.Sprintf("\n(%d instructions from offset 0x%x, arch=arm, mode=32)", decoded, offset))
	return sb.String(), nil
}

// disasmResolved holds the result of VA resolution for any binary format.
type disasmResolved struct {
	fileOffset     int64
	displayBase    uint64
	arch           string // "x86" or "arm"
	mode           int    // 16, 32, or 64
	funcEndFileOff int64  // -1 if unknown
	// endNote explains the funcEndFileOff boundary once the output reaches
	// it (endVA is that boundary's VA); nil when there is nothing to add.
	endNote func(endVA uint64) string
	symbols map[uint64]string
	closer         func() // close the binary file handle
}

// disasmResolveVA tries PE, then ELF, then Mach-O to resolve a VA to file offset.
func disasmResolveVA(filePath, vaStr string) (*disasmResolved, error) {
	va, err := parseHexAddr(vaStr)
	if err != nil {
		return nil, fmt.Errorf("invalid va: %s", vaStr)
	}

	// Try PE first
	if r, err := disasmResolvePE(filePath, va); err == nil {
		return r, nil
	}
	// Try ELF
	if r, err := disasmResolveELF(filePath, va); err == nil {
		return r, nil
	}
	// Try Mach-O
	if r, err := disasmResolveMachO(filePath, va); err == nil {
		return r, nil
	}

	return nil, fmt.Errorf("va parameter requires a PE, ELF, or Mach-O file (could not parse %s)", filePath)
}

func disasmResolvePE(filePath string, va uint64) (*disasmResolved, error) {
	f, err := pe.Open(filePath)
	if err != nil {
		return nil, err
	}

	imageBase := peImageBase(f)
	if va < imageBase || va-imageBase > 0xFFFFFFFF {
		f.Close()
		return nil, fmt.Errorf("va out of range")
	}

	rva := uint32(va - imageBase)
	fileOff, _, err := rvaToFileOffset(f, rva)
	if err != nil {
		f.Close()
		return nil, err
	}

	r := &disasmResolved{
		fileOffset:     int64(fileOff),
		displayBase:    va - uint64(fileOff),
		funcEndFileOff: -1,
		closer:         func() { f.Close() },
	}

	// Auto-detect arch/mode from PE Machine field
	switch f.FileHeader.Machine {
	case 0x14c: // i386
		r.arch = "x86"
		r.mode = 32
	case 0x8664: // AMD64
		r.arch = "x86"
		r.mode = 64
	case 0xaa64: // ARM64
		r.arch = "arm"
		r.mode = 64
	case 0x01c0, 0x01c2, 0x01c4: // ARM, ARMv7 Thumb, ARMv7
		r.arch = "arm"
		r.mode = 32
	}

	// Function boundary from .pdata or heuristic
	if endOff, heuristic, found := pdataOrHeuristicEndOffset(f, rva, uint32(fileOff)); found {
		r.funcEndFileOff = int64(endOff)
		if heuristic {
			r.endNote = func(endVA uint64) string {
				return fmt.Sprintf("\n** stopped at the estimated function end 0x%x (no .pdata entry; heuristic boundary). "+
					"If the code continues, disassemble with va=\"0x%x\". **", endVA, endVA)
			}
		} else {
			// f stays open until the caller's closer runs, so the unwind
			// info is read only when the output actually reaches the end.
			r.endNote = func(uint64) string { return pdataFragmentsNote(loadPdata(f, imageBase), imageBase, rva) }
		}
	}

	r.symbols = peSymbolMap(f, imageBase)
	mergePDBNames(r.symbols, filePath, "", false, f, imageBase)
	return r, nil
}

func disasmResolveELF(filePath string, va uint64) (*disasmResolved, error) {
	f, err := elf.Open(filePath)
	if err != nil {
		return nil, err
	}

	// ELF imageBase = lowest PT_LOAD virtual address (unlike PE which stores
	// it in the optional header). Needed for symbol map VA keys.
	var imageBase uint64
	foundLoad := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			if !foundLoad || p.Vaddr < imageBase {
				imageBase = p.Vaddr
				foundLoad = true
			}
		}
	}

	// Resolve VA to file offset via section headers
	var fileOff int64 = -1
	for _, sec := range f.Sections {
		if sec.Type == elf.SHT_NOBITS {
			continue // .bss has no file data
		}
		secEnd := sec.Addr + sec.Size
		if secEnd < sec.Addr {
			continue // overflow in malformed section header
		}
		if va >= sec.Addr && va < secEnd {
			fileOff = int64(sec.Offset) + int64(va-sec.Addr)
			break
		}
	}
	if fileOff < 0 {
		f.Close()
		return nil, fmt.Errorf("va 0x%x not found in any ELF section", va)
	}

	r := &disasmResolved{
		fileOffset:     fileOff,
		displayBase:    va - uint64(fileOff),
		funcEndFileOff: -1,
		closer:         func() { f.Close() },
	}

	// Auto-detect arch/mode
	switch f.Machine {
	case elf.EM_386:
		r.arch = "x86"
		r.mode = 32
	case elf.EM_X86_64:
		r.arch = "x86"
		r.mode = 64
	case elf.EM_AARCH64:
		r.arch = "arm"
		r.mode = 64
	case elf.EM_ARM:
		r.arch = "arm"
		r.mode = 32
	}

	r.symbols = elfSymbolMap(f, imageBase)
	return r, nil
}

func disasmResolveMachO(filePath string, va uint64) (*disasmResolved, error) {
	f, err := macho.Open(filePath)
	if err != nil {
		return nil, err
	}

	// Mach-O imageBase = __TEXT segment vmaddr (conventional base for code).
	// Needed for symbol map VA keys.
	var imageBase uint64
	for _, seg := range f.Loads {
		if s, ok := seg.(*macho.Segment); ok && s.Name == "__TEXT" {
			imageBase = s.Addr
			break
		}
	}

	// Resolve VA to file offset via sections
	var fileOff int64 = -1
	for _, sec := range f.Sections {
		secEnd := sec.Addr + sec.Size
		if secEnd < sec.Addr {
			continue // overflow in malformed section header
		}
		if va >= sec.Addr && va < secEnd {
			fileOff = int64(sec.Offset) + int64(va-sec.Addr)
			break
		}
	}
	if fileOff < 0 {
		f.Close()
		return nil, fmt.Errorf("va 0x%x not found in any Mach-O section", va)
	}

	r := &disasmResolved{
		fileOffset:     fileOff,
		displayBase:    va - uint64(fileOff),
		funcEndFileOff: -1,
		closer:         func() { f.Close() },
	}

	// Auto-detect arch/mode
	switch f.Cpu {
	case macho.Cpu386:
		r.arch = "x86"
		r.mode = 32
	case macho.CpuAmd64:
		r.arch = "x86"
		r.mode = 64
	case macho.CpuArm64:
		r.arch = "arm"
		r.mode = 64
	case macho.CpuArm:
		r.arch = "arm"
		r.mode = 32
	}

	r.symbols = machoSymbolMap(f, imageBase)
	return r, nil
}

// pdataFragmentsNote lists the other .pdata ranges of the function that owns
// rva when the compiler split it (UNW_FLAG_CHAININFO fragments), or "" when
// the range is the whole function.
func pdataFragmentsNote(pd *pdataIndex, imageBase uint64, rva uint32) string {
	if pd == nil {
		return ""
	}
	cur := findFunc(pd.table, rva)
	if cur == nil {
		return ""
	}
	ownerOf := func(begin uint32) uint32 {
		if p, ok := pd.primary[begin]; ok {
			return p
		}
		return begin
	}
	owner := ownerOf(cur.begin)
	var others []string
	for _, fr := range pd.table {
		if fr.begin != cur.begin && ownerOf(fr.begin) == owner {
			others = append(others, fmt.Sprintf("0x%x-0x%x", imageBase+uint64(fr.begin), imageBase+uint64(fr.end)))
		}
	}
	if len(others) == 0 {
		return ""
	}
	const maxListed = 16
	more := ""
	if len(others) > maxListed {
		more = fmt.Sprintf(", ... (%d more)", len(others)-maxListed)
		others = others[:maxListed]
	}
	of := ""
	if owner != cur.begin {
		of = fmt.Sprintf(" This range is a split-off fragment of the function at 0x%x.", imageBase+uint64(owner))
	}
	return fmt.Sprintf("\n** reached the end of this .pdata range, but the function is split into %d range(s).%s "+
		"Other ranges: %s%s. Disassemble each with va=<start>. **", len(others)+1, of, strings.Join(others, ", "), more)
}

// resolveSymbol looks up target addresses in the symbol map for CALL/JMP/LEA instructions.
// Returns the symbol name if found, empty string otherwise.
func resolveSymbol(inst x86asm.Inst, instrAddr uint64, symbols map[uint64]string, mode int) string {
	if len(symbols) == 0 {
		return ""
	}

	nextAddr := instrAddr + uint64(inst.Len)

	for _, arg := range inst.Args {
		if arg == nil {
			break
		}
		switch a := arg.(type) {
		case x86asm.Rel:
			// E8/E9 relative CALL/JMP: target = instrAddr + instLen + rel
			target := nextAddr + uint64(int64(a))
			if name, ok := symbols[target]; ok {
				return name
			}
		case x86asm.Mem:
			// RIP-relative memory: FF 15 [rip+disp32], LEA reg, [rip+disp32]
			if mode == 64 && a.Base == x86asm.RIP && a.Index == 0 && a.Scale == 0 {
				target := nextAddr + uint64(memDisp(a))
				if name, ok := symbols[target]; ok {
					return name
				}
			}
		case x86asm.Imm:
			// Immediate address (32-bit mode): PUSH addr, CALL addr
			target := uint64(a)
			if name, ok := symbols[target]; ok {
				return name
			}
		}
	}
	return ""
}
