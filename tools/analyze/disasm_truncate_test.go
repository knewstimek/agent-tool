package analyze

import (
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func disasmTest(data []byte, base uint64, count, mode int, stopAtRet bool) string {
	out, _, _ := disasmX86Run(data, base, 0, count, mode, disasmOpts{stopAtRet: stopAtRet})
	return out
}

// The instruction cap must (a) limit output to `count` instructions, and
// (b) emit a truncation hint with a resume VA when it cuts mid-function -- but
// NOT when the disassembly ends naturally (data exhausted). Guards the
// pagination contract the agent relies on.
func TestDisasmTruncationHint(t *testing.T) {
	// 6x `nop` (0x90) then data continues -- decoding 2 must truncate with a hint.
	nops := []byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90}
	out := disasmTest(nops, 0x401000, 2, 32, false)
	if strings.Count(out, "nop") != 2 {
		t.Errorf("expected exactly 2 instructions, got:\n%s", out)
	}
	if !strings.Contains(out, "truncated at the 2-instruction cap") {
		t.Errorf("expected truncation hint, got:\n%s", out)
	}
	// Resume VA = base + 2 consumed bytes (2 nops) = 0x401002.
	if !strings.Contains(out, "va=\"0x401002\"") {
		t.Errorf("expected resume va 0x401002, got:\n%s", out)
	}

	// Exactly enough data (2 nops): cap reached but nothing ahead -> no hint.
	twoNops := []byte{0x90, 0x90}
	out2 := disasmTest(twoNops, 0x401000, 2, 32, false)
	if strings.Contains(out2, "truncated") {
		t.Errorf("no truncation hint expected when data is exhausted, got:\n%s", out2)
	}

	// stop_at_ret hitting a real boundary must not be flagged as truncated.
	// ret (C3) followed by int3 padding = confirmed boundary.
	retPad := []byte{0x90, 0xC3, 0xCC, 0xCC}
	out3 := disasmTest(retPad, 0x401000, 50, 32, true)
	if !strings.Contains(out3, "stopped at function return") {
		t.Errorf("expected ret-stop, got:\n%s", out3)
	}
	if strings.Contains(out3, "truncated") {
		t.Errorf("ret-boundary must not be flagged truncated, got:\n%s", out3)
	}
}

// The hex encoding column is opt-in: without show_bytes a line is address and
// instruction only.
func TestDisasmShowBytes(t *testing.T) {
	code := []byte{0x48, 0x89, 0xc8, 0xc3} // mov rax, rcx; ret
	plain, _, _ := disasmX86Run(code, 0x140001000, 0, 10, 64, disasmOpts{})
	if !strings.Contains(plain, "0x140001000:  mov rax, rcx\n") || strings.Contains(plain, "48 89 c8") {
		t.Errorf("default listing should omit bytes, got:\n%s", plain)
	}
	withBytes, _, _ := disasmX86Run(code, 0x140001000, 0, 10, 64, disasmOpts{showBytes: true})
	if !strings.Contains(withBytes, "0x140001000:  48 89 c8") {
		t.Errorf("show_bytes listing should carry the encoding, got:\n%s", withBytes)
	}
}

// An MSVC x64 switch table placed after the function's code is printed as one
// data line and skipped, not decoded as instructions.
func TestDisasmSwitchTableAsData(t *testing.T) {
	const base = 0x140001000 // image base 0x140000000, code at RVA 0x1000
	code := []byte{
		0x83, 0xf9, 0x02, // 0x00 cmp ecx, 2
		0x77, 0x11, // 0x03 ja 0x18
		0x48, 0x8d, 0x15, 0xf4, 0xef, 0xff, 0xff, // 0x05 lea rdx, [__ImageBase]
		0x8b, 0x84, 0x8a, 0x1c, 0x10, 0x00, 0x00, // 0x0c mov eax, [rdx+rcx*4+0x101c]
		0x48, 0x01, 0xd0, // 0x13 add rax, rdx
		0xff, 0xe0, // 0x16 jmp rax
		0xc3, 0xc3, 0xc3, // 0x18..0x1a cases
		0xcc,                   // 0x1b padding
		0x18, 0x10, 0x00, 0x00, // 0x1c table: RVA 0x1018
		0x19, 0x10, 0x00, 0x00, //            RVA 0x1019
		0x1a, 0x10, 0x00, 0x00, //            RVA 0x101a
		0x90, // 0x28 nop: sweep resumes in step after the table
	}
	out, _, _ := disasmX86Run(code, base, 0, 100, 64, disasmOpts{})
	want := "0x14000101c:  ; switch table, 3 x 4-byte entries (data, not code) -> 0x140001018, 0x140001019, 0x14000101a\n0x140001028:  nop\n"
	if !strings.Contains(out, want) {
		t.Errorf("switch table not rendered as data, got:\n%s", out)
	}
}

// MSVC maps case values through a byte index table first; the bounds check
// counts case values (4 here), not entries (2). Both tables print as data.
func TestDisasmSwitchByteIndexTable(t *testing.T) {
	const base = 0x140001000
	code := []byte{
		0x83, 0xf9, 0x03, // 0x00 cmp ecx, 3
		0x77, 0x1b, // 0x03 ja 0x20
		0x48, 0x8d, 0x15, 0xf4, 0xef, 0xff, 0xff, // 0x05 lea rdx, [__ImageBase]
		0x0f, 0xb6, 0x8c, 0x0a, 0x2c, 0x10, 0x00, 0x00, // 0x0c movzx ecx, byte [rdx+rcx+0x102c]
		0x8b, 0x84, 0x8a, 0x24, 0x10, 0x00, 0x00, // 0x14 mov eax, [rdx+rcx*4+0x1024]
		0x48, 0x01, 0xd0, // 0x1b add rax, rdx
		0xff, 0xe0, // 0x1e jmp rax
		0xc3, 0xc3, // 0x20, 0x21 cases
		0xcc, 0xcc, // padding
		0x20, 0x10, 0x00, 0x00, 0x21, 0x10, 0x00, 0x00, // 0x24 entry table
		0x00, 0x01, 0x01, 0x00, // 0x2c index table
		0x90, // 0x30
	}
	out, _, _ := disasmX86Run(code, base, 0, 100, 64, disasmOpts{})
	for _, want := range []string{
		"0x140001024:  ; switch table, 2 x 4-byte entries (data, not code) -> 0x140001020, 0x140001021\n",
		"0x14000102c:  ; switch index table, 4 bytes (data, not code): case value -> entry 0,1,1,0\n",
		"0x140001030:  nop\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	read := func(va uint64, n int) []byte {
		if va < base || va-base+uint64(n) > uint64(len(code)) {
			return nil
		}
		return code[va-base : va-base+uint64(n)]
	}
	inCode := func(va uint64) bool { return va >= base && va < base+uint64(len(code)) }
	jmp, _ := x86asm.Decode(code[0x1e:], 64)
	if got := switchCases(code, base, 0x1e, jmp, 64, read, inCode); len(got) != 2 {
		t.Errorf("switchCases = %#x, want the 2 entry targets", got)
	}
}
