package analyze

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Gap functions: a body ends where its control flow ends, the next starts
// after int3 padding; a jump to distant code does not swallow the functions
// in between, and a switch through a register runs to the next padding.
func TestGapFunctionsX64(t *testing.T) {
	var code []byte
	at := func() int { return len(code) }
	emit := func(b ...byte) { code = append(code, b...) }
	pad := func() {
		for len(code)%16 != 0 {
			emit(0xCC)
		}
	}
	f1 := at()
	emit(0x31, 0xC0) // xor eax, eax
	emit(0x74, 0x00) // je +0 (stays inside)
	jmpFar := at()
	emit(0xE9, 0, 0, 0, 0) // jmp far shared code (patched below)
	pad()
	f2 := at()
	emit(0x48, 0x89, 0xC8, 0xC3) // mov rax, rcx; ret
	pad()
	f3 := at()
	emit(0xFF, 0xE0)       // jmp rax (switch dispatch)
	emit(0xB8, 1, 0, 0, 0) // case: mov eax, 1
	emit(0xC3)             // ret
	pad()
	f4 := at()
	emit(0xC3)
	pad()
	shared := at()
	emit(0x90, 0xC3)
	binary.LittleEndian.PutUint32(code[jmpFar+1:], uint32(shared-(jmpFar+5)))

	got := gapFunctions(code, 64, map[int]bool{}, 0x1000)
	if want := []int{f1, f2, f3, f4, shared}; !reflect.DeepEqual(got, want) {
		t.Errorf("starts %x, want %x", got, want)
	}
}

// x86: a switch table embedded after its function is skipped over as data,
// and nop padding separates functions.
func TestGapFunctionsX86SwitchTable(t *testing.T) {
	const base = 0x401000
	code := []byte{
		0xFF, 0x24, 0x85, 0, 0, 0, 0, // jmp [eax*4+table]
		0xB8, 1, 0, 0, 0, 0xC3, // case 0
		0xB8, 2, 0, 0, 0, 0xC3, // case 1
		0x90, // align
	}
	table := len(code)
	binary.LittleEndian.PutUint32(code[3:], uint32(base+table))
	code = binary.LittleEndian.AppendUint32(code, base+7)
	code = binary.LittleEndian.AppendUint32(code, base+13)
	next := len(code)
	code = append(code, 0x8B, 0x41, 0x08, 0xC3) // mov eax, [ecx+8]; ret
	got := gapFunctions(code, 32, map[int]bool{}, base)
	if want := []int{0, next}; !reflect.DeepEqual(got, want) {
		t.Errorf("starts %x, want %x", got, want)
	}
}

// .pdata ranges stay exact: a start inside one (a branch target) does not
// split it, while estimated ranges are re-ranged by new starts.
func TestAddGapStartsKeepsPdata(t *testing.T) {
	sec := []cgSection{{rva: 0x1000, data: make([]byte, 0x400)}}
	base := []funcRange{{begin: 0x1000, end: 0x1100, exact: true}, {begin: 0x1200, end: 0x1400}}
	got := addGapStarts(base, []uint32{0x1050, 0x1150, 0x1300}, sec)
	want := []funcRange{
		{begin: 0x1000, end: 0x1100, exact: true},
		{begin: 0x1150, end: 0x1200},
		{begin: 0x1200, end: 0x1300},
		{begin: 0x1300, end: 0x1400},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("table %+v\nwant %+v", got, want)
	}
}

// Callers through a thunk (a function that only jumps to the target) are
// reported as callers of the target, and tail jumps are marked.
func TestFindCallersThunkAndTail(t *testing.T) {
	data := make([]byte, 0x100)
	put := func(at int, op byte, to int) {
		data[at] = op
		binary.LittleEndian.PutUint32(data[at+1:], uint32(to-(at+5)))
	}
	const target, thunk, caller, tailer = 0x80, 0x40, 0x00, 0x20
	put(thunk, 0xE9, target)   // thunk: jmp target
	put(caller+3, 0xE8, thunk) // caller: call thunk
	put(tailer+2, 0xE9, target)
	table := []funcRange{{begin: 0x00, end: 0x20}, {begin: 0x20, end: 0x40}, {begin: 0x40, end: 0x45}, {begin: 0x80, end: 0x90}}
	got := findCallers([]cgSection{{rva: 0, data: data}}, target, table)
	want := []cgCaller{{rva: caller, thunk: thunk}, {rva: tailer, tail: true}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("callers %+v, want %+v", got, want)
	}
}

// Immediates and absolute operands carrying the target are found by decode
// (x86 mov ecx, imm32; x64 mov rax, imm64), and an address load feeding a
// register call becomes a CALL.
func TestXrefImmediates(t *testing.T) {
	x86 := []byte{0x90, 0xB9, 0x00, 0x20, 0x40, 0x00, 0xC3} // mov ecx, 0x402000
	target := xrefTargetRange{imageBase: 0x400000, startVA: 0x402000, endVA: 0x402000, startRVA: 0x2000, endRVA: 0x2000}
	refs, n := collectXrefImm(x86, 0x1000, target, 32, map[uint64]bool{}, 10, 0, nil)
	if n != 1 || !strings.Contains(refs[0].line, "0x401001: MOV ecx, 0x402000") {
		t.Errorf("x86 imm: %v", refs)
	}

	x64 := []byte{0x48, 0xB8, 0x00, 0x20, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0xC3} // mov rax, imm64; call rax
	target64 := xrefTargetRange{imageBase: 0x140000000, startVA: 0x140002000, endVA: 0x140002000, startRVA: 0x2000, endRVA: 0x2000}
	refs, n = collectXrefImm(x64, 0x1000, target64, 64, map[uint64]bool{}, 10, 0, nil)
	if n != 1 {
		t.Fatalf("x64 imm64 not found: %v", refs)
	}
	bin := &xrefBinary{imageBase: 0x140000000, arch: "x64", sections: []xrefSection{{rva: 0x1000, data: x64}}}
	annotateXrefs(bin, nil, refs)
	if refs[0].refType != "CALL" || !strings.Contains(refs[0].line, "then call rax at 0x14000100a") {
		t.Errorf("indirect call not recognized: %+v", refs[0])
	}
}

// Data pointers: with a relocation table only relocated slots count; PIE
// RELATIVE relocations supply pointers the file stores as 0.
func TestXrefDataPointers(t *testing.T) {
	data := make([]byte, 0x20)
	binary.LittleEndian.PutUint64(data[0x00:], 0x140001000) // relocated vtable slot
	binary.LittleEndian.PutUint64(data[0x10:], 0x140001000) // same value, not relocated: a constant
	bin := &xrefBinary{imageBase: 0x140000000, arch: "x64",
		dataSections: []xrefDataSection{{name: ".rdata", rva: 0x3000, data: data}},
		relocSlots:   []uint32{0x3000}, hasRelocs: true}
	target := bin.target(0x140001000, 0x140001000)
	refs, n := collectXrefData(bin, target, 10, 0, nil)
	if n != 1 || !strings.HasPrefix(refs[0].line, "  0x140003000: pointer to 0x140001000 in .rdata") {
		t.Errorf("reloc-checked pointers: %v", refs)
	}

	pie := &xrefBinary{imageBase: 0, arch: "x64",
		dataSections: []xrefDataSection{{name: ".data.rel.ro", rva: 0x4000, data: make([]byte, 8)}},
		relative:     map[uint32]uint32{0x4000: 0x1000}}
	refs, n = collectXrefData(pie, pie.target(0x1000, 0x1000), 10, 0, nil)
	if n != 1 || !strings.Contains(refs[0].line, "RELATIVE relocation") {
		t.Errorf("PIE pointers: %v", refs)
	}
}

// Text search widens a match to its whole string and finds UTF-16 too.
func TestFindXrefStrings(t *testing.T) {
	data := []byte("\x00Login failed: %s\x00")
	wide := []byte{0, 0}
	for _, r := range "Hello" {
		wide = append(wide, byte(r), 0)
	}
	wide = append(wide, 0, 0)
	bin := &xrefBinary{imageBase: 0x400000, dataSections: []xrefDataSection{
		{name: ".rdata", rva: 0x1000, data: data},
		{name: ".data", rva: 0x2000, data: wide},
	}}
	got := findXrefStrings(bin, "failed")
	if len(got) != 1 || got[0].va != 0x401001 || got[0].text != "Login failed: %s" {
		t.Errorf("narrow: %+v", got)
	}
	got = findXrefStrings(bin, "ell")
	if len(got) != 1 || !got[0].wide || got[0].va != 0x402002 || got[0].text != "Hello" {
		t.Errorf("wide: %+v", got)
	}
}

// Field xref on the PDB fixture: an inherited member resolves through the
// base class, and the method that touches it is confirmed by decompiling.
func TestXrefFieldFixture(t *testing.T) {
	exe := filepath.Join("testdata", "pdb", "fixture_x64.exe")
	off, _, owners, err := resolveFieldOffset(exe, "", false, "geo::Rect", "id_")
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) < 2 || owners[0] != "geo::Rect" {
		t.Errorf("id_ at 0x%x owners %v: want the base class after geo::Rect", off, owners)
	}
	out, err := opXref(context.Background(), AnalyzeInput{FilePath: exe, Field: "geo::Rect::w_"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Accesses confirmed") || !strings.Contains(out, "geo::Rect::area") || !strings.Contains(out, "->w_") {
		t.Errorf("field xref:\n%s", out)
	}
	if _, err := opXref(context.Background(), AnalyzeInput{FilePath: exe, Field: "geo::Rect::nope"}); err == nil || !strings.Contains(err.Error(), "w_") {
		t.Errorf("unknown member should list members, got %v", err)
	}
}
