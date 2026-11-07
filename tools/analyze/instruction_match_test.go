package analyze

import (
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// register + displacement names a [reg+disp] operand, stack pointer included:
// `call [rsp+0xf8]` has no register operand, and a displacement alone skips
// stack bases (locals, not structure fields).
func TestInstructionMatchesRegisterInMemory(t *testing.T) {
	callRSP, err := x86asm.Decode([]byte{0xff, 0x94, 0x24, 0xf8, 0x00, 0x00, 0x00}, 64) // call [rsp+0xf8]
	if err != nil {
		t.Fatal(err)
	}
	movRCX, err := x86asm.Decode([]byte{0x48, 0x8b, 0x88, 0xf8, 0x00, 0x00, 0x00}, 64) // mov rcx, [rax+0xf8]
	if err != nil {
		t.Fatal(err)
	}
	rsp := instructionSearchSpec{hasRegister: true, regFamily: 4, regWidth: 64, hasDisp: true, displacement: 0xf8}
	rcx := instructionSearchSpec{hasRegister: true, regFamily: 1, regWidth: 64, hasDisp: true, displacement: 0xf8}
	rax := instructionSearchSpec{hasRegister: true, regFamily: 0, regWidth: 64, hasDisp: true, displacement: 0xf8}
	dispOnly := instructionSearchSpec{hasDisp: true, displacement: 0xf8}
	regOnlyRSP := instructionSearchSpec{hasRegister: true, regFamily: 4, regWidth: 64}
	cases := []struct {
		name string
		inst x86asm.Inst
		spec instructionSearchSpec
		want bool
	}{
		{"rsp base named", callRSP, rsp, true},
		{"stack base skipped without register", callRSP, dispOnly, false},
		{"register alone is an operand filter", callRSP, regOnlyRSP, false},
		{"register operand with field disp", movRCX, rcx, true},
		{"base register named", movRCX, rax, true},
		{"field disp alone", movRCX, dispOnly, true},
		{"other register", movRCX, rsp, false},
	}
	for _, c := range cases {
		if got := instructionMatches(c.inst, c.spec); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
