package analyze

import (
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func testSearchBinary(code []byte, functions ...funcRange) *cgBinary {
	return &cgBinary{
		imageBase:    0x140000000,
		is64:         true,
		arch:         "x64",
		format:       "PE",
		symbols:      map[uint64]string{},
		execSections: []cgSection{{rva: 0x1000, data: code}},
		funcTable:    functions,
	}
}

func TestInstructionSearchFindsR9DImmediateAndClassifiesRecovery(t *testing.T) {
	// The first MOV is reachable from the known function start. The second is
	// outside every known function but still decodes at an executable-section
	// byte offset, exercising the exhaustive recovery lane.
	code := []byte{
		0x41, 0xB9, 0x27, 0x03, 0x00, 0x00, // mov r9d,0x327
		0xC3,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x41, 0xB9, 0x27, 0x03, 0x00, 0x00, // recovered candidate
	}
	bin := testSearchBinary(code, funcRange{begin: 0x1000, end: 0x1007})
	spec := instructionSearchSpec{mnemonic: "MOV", regFamily: 9, regWidth: 32, hasRegister: true, immediate: 0x327, hasImmediate: true}

	reachable, interiors, _, complete := analyzeInstructionFlows(bin, spec, false, 20)
	if !complete {
		t.Fatal("unexpected analysis budget exhaustion")
	}
	hits, total := exhaustiveInstructionMatches(bin, spec, reachable, interiors, 20)
	if total != 2 || len(hits) != 2 {
		t.Fatalf("hits=%d total=%d, want 2/2: %+v", len(hits), total, hits)
	}
	if hits[0].confidence != "confirmed" || hits[1].confidence != "candidate" {
		t.Fatalf("confidence = %q/%q, want confirmed/candidate", hits[0].confidence, hits[1].confidence)
	}
	if !strings.Contains(strings.ToLower(hits[0].text), "mov r9d, 0x327") {
		t.Fatalf("unexpected decoded instruction: %q", hits[0].text)
	}
}

func TestInstructionSearchDoesNotDecodeInsideConfirmedREXInstruction(t *testing.T) {
	code := []byte{0x41, 0xB9, 0x27, 0x03, 0x00, 0x00, 0xC3}
	bin := testSearchBinary(code, funcRange{begin: 0x1000, end: 0x1007})
	spec := instructionSearchSpec{immediate: 0x327, hasImmediate: true}
	reachable, interiors, _, _ := analyzeInstructionFlows(bin, spec, false, 20)

	hits, total := exhaustiveInstructionMatches(bin, spec, reachable, interiors, 20)
	if total != 1 || len(hits) != 1 || hits[0].rva != 0x1000 {
		t.Fatalf("REX instruction was duplicated by a mid-instruction decode: total=%d hits=%+v", total, hits)
	}
}

func TestInstructionSearchTracesComputedX64CallArgument(t *testing.T) {
	code := []byte{
		0x41, 0xB9, 0x00, 0x03, 0x00, 0x00, // mov r9d,0x300
		0x41, 0x83, 0xC1, 0x27, // add r9d,0x27
		0xE8, 0x00, 0x00, 0x00, 0x00, // call next instruction
		0xC3,
	}
	bin := testSearchBinary(code, funcRange{begin: 0x1000, end: 0x1010})
	spec := instructionSearchSpec{immediate: 0x327, hasImmediate: true}

	_, _, traces, complete := analyzeInstructionFlows(bin, spec, true, 20)
	if !complete {
		t.Fatal("unexpected analysis budget exhaustion")
	}
	joined := traceText(traces)
	if !strings.Contains(strings.ToUpper(joined), "ADD") || !strings.Contains(joined, "R9D=0x327") {
		t.Fatalf("computed producer missing from traces:\n%s", joined)
	}
	if !strings.Contains(joined, "arg4 R9/R9D=0x327") {
		t.Fatalf("x64 call argument link missing from traces:\n%s", joined)
	}
}

func TestInstructionSearchTracesSimpleStackRoundTrip(t *testing.T) {
	code := []byte{
		0x48, 0x83, 0xEC, 0x28, // sub rsp,0x28
		0xC7, 0x44, 0x24, 0x20, 0x27, 0x03, 0x00, 0x00, // mov [rsp+0x20],0x327
		0x44, 0x8B, 0x4C, 0x24, 0x20, // mov r9d,[rsp+0x20]
		0xE8, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x83, 0xC4, 0x28, // add rsp,0x28
		0xC3,
	}
	bin := testSearchBinary(code, funcRange{begin: 0x1000, end: 0x101B})
	spec := instructionSearchSpec{immediate: 0x327, hasImmediate: true}

	_, _, traces, _ := analyzeInstructionFlows(bin, spec, true, 20)
	joined := traceText(traces)
	if !strings.Contains(joined, "arg4 R9/R9D=0x327") {
		t.Fatalf("stack round-trip did not reach R9 call argument:\n%s", joined)
	}
}

func TestInstructionSearchMergesBranchConstantsConservatively(t *testing.T) {
	code := []byte{
		0x85, 0xC0, // test eax,eax
		0x74, 0x08, // je alternate (offset 12)
		0x41, 0xB9, 0x00, 0x03, 0x00, 0x00, // mov r9d,0x300
		0xEB, 0x06, // jmp join (offset 18)
		0x41, 0xB9, 0x00, 0x04, 0x00, 0x00, // alternate: mov r9d,0x400
		0x41, 0x83, 0xC1, 0x27, // join: add r9d,0x27
		0xE8, 0x00, 0x00, 0x00, 0x00,
		0xC3,
	}
	bin := testSearchBinary(code, funcRange{begin: 0x1000, end: 0x101C})
	spec := instructionSearchSpec{immediate: 0x327, hasImmediate: true}

	_, _, traces, _ := analyzeInstructionFlows(bin, spec, true, 20)
	var foundPossible bool
	for _, hit := range traces {
		if strings.Contains(hit.text, "arg4 R9/R9D=0x327") && hit.possible {
			foundPossible = true
		}
	}
	if !foundPossible {
		t.Fatalf("branch alternatives were not preserved as a possible call value:\n%s", traceText(traces))
	}
}

func TestInstructionSearchSpecAcceptsIntelExtendedRegisterNames(t *testing.T) {
	spec, err := parseInstructionSearchSpec(AnalyzeInput{Mnemonic: "mov", Register: "r9d", Immediate: "0x327"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.mnemonic != "MOV" || spec.regFamily != 9 || spec.regWidth != 32 || spec.immediate != 0x327 {
		t.Fatalf("unexpected parsed spec: %+v", spec)
	}
}

func TestInstructionSearchMatchesImmediateAcrossInstructionEncodings(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{"mov extended register", []byte{0x41, 0xB9, 0x27, 0x03, 0x00, 0x00}},
		{"mov sign-extended register", []byte{0x49, 0xC7, 0xC1, 0x27, 0x03, 0x00, 0x00}},
		{"mov stack slot", []byte{0xC7, 0x44, 0x24, 0x20, 0x27, 0x03, 0x00, 0x00}},
		{"push", []byte{0x68, 0x27, 0x03, 0x00, 0x00}},
	}
	spec := instructionSearchSpec{immediate: 0x327, hasImmediate: true}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst, err := x86asm.Decode(tt.code, 64)
			if err != nil {
				t.Fatal(err)
			}
			if !instructionMatches(inst, spec) {
				t.Fatalf("immediate search did not match %s", x86asm.IntelSyntax(inst, 0x140001000, nil))
			}
		})
	}
}

func TestInstructionSearchTracesX86PushedArgument(t *testing.T) {
	code := []byte{
		0x68, 0x27, 0x03, 0x00, 0x00, // push 0x327
		0xE8, 0x00, 0x00, 0x00, 0x00,
		0x83, 0xC4, 0x04, // add esp,4
		0xC3,
	}
	bin := testSearchBinary(code, funcRange{begin: 0x1000, end: 0x100E})
	bin.is64, bin.arch = false, "x86"
	spec := instructionSearchSpec{immediate: 0x327, hasImmediate: true}

	_, _, traces, _ := analyzeInstructionFlows(bin, spec, true, 20)
	if joined := traceText(traces); !strings.Contains(joined, "stack arg1=0x327") {
		t.Fatalf("x86 pushed argument was not traced:\n%s", joined)
	}
}

func TestInstructionSearchImmediateLeadingZeroIsDecimal(t *testing.T) {
	v, err := parseInstructionImmediate("0807")
	if err != nil || v != 807 {
		t.Fatalf("parseInstructionImmediate(0807) = %d, %v; want decimal 807", v, err)
	}
}

func TestInstructionSearchPEIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("whole executable-section integration scan")
	}
	result, err := opInstructionSearch(AnalyzeInput{
		FilePath:   testBinary,
		Mnemonic:   "RET",
		MaxResults: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "Direct instruction matches") || !strings.Contains(result, "[confirmed]") {
		t.Fatalf("unexpected integration output:\n%s", result)
	}
}

func traceText(hits []valueTraceHit) string {
	var lines []string
	for _, hit := range hits {
		lines = append(lines, hit.text)
	}
	return strings.Join(lines, "\n")
}
