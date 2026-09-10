package analyze

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func testXrefRange(imageBase uint64, startRVA, endRVA uint32) xrefTargetRange {
	return xrefTargetRange{
		imageBase: imageBase,
		startVA:   imageBase + uint64(startRVA),
		endVA:     imageBase + uint64(endRVA),
		startRVA:  startRVA,
		endRVA:    endRVA,
	}
}

func TestCollectXref64_OptionalRange(t *testing.T) {
	const (
		imageBase = uint64(0x140000000)
		secRVA    = uint32(0x1000)
		targetRVA = uint32(0x2020)
	)
	data := make([]byte, 7)
	data[0], data[1], data[2] = 0x48, 0x8D, 0x05 // LEA rax,[rip+disp32]
	disp := int32(targetRVA) - int32(secRVA+uint32(len(data)))
	binary.LittleEndian.PutUint32(data[3:], uint32(disp))

	exact := testXrefRange(imageBase, 0x2000, 0x2000)
	if _, found := collectXref64(data, secRVA, exact, 10, 0, nil); found != 0 {
		t.Fatalf("exact search unexpectedly matched an interior range address")
	}

	rng := testXrefRange(imageBase, 0x2000, 0x20ff)
	refs, found := collectXref64(data, secRVA, rng, 10, 0, nil)
	if found != 1 || len(refs) != 1 {
		t.Fatalf("range search found %d references, want 1", found)
	}
	wantVA := imageBase + uint64(targetRVA)
	if !strings.Contains(refs[0].line, fmt.Sprintf("0x%x", wantVA)) {
		t.Fatalf("range result does not report actual target 0x%x: %s", wantVA, refs[0].line)
	}
}

func TestCollectXref64_RIPRelativeMOV32_ExactAndRange(t *testing.T) {
	const (
		imageBase = uint64(0x140000000)
		secRVA    = uint32(0x6400)
		targetRVA = uint32(0x16e9c)
	)
	// 8B 05 96 0A 01 00 = mov eax, [rip+0x10a96].  This is the
	// xhunter1.sys encoding reported at RVA 0x6400.
	data := []byte{0x8B, 0x05, 0x96, 0x0A, 0x01, 0x00}

	for _, target := range []xrefTargetRange{
		testXrefRange(imageBase, targetRVA, targetRVA),
		testXrefRange(imageBase, targetRVA-1, targetRVA+1),
	} {
		refs, found := collectXref64(data, secRVA, target, 10, 0, nil)
		if found != 1 || len(refs) != 1 {
			t.Fatalf("xref to %s found %d references, want 1", target.label(), found)
		}
		if !strings.Contains(refs[0].line, "MOV eax") || !strings.Contains(refs[0].line, "0x140006400") || !strings.Contains(refs[0].line, "0x140016e9c") {
			t.Fatalf("unexpected MOV xref: %s", refs[0].line)
		}
	}
}

func TestCollectXref64_RIPRelativeMOV64IsNotDuplicatedAsMOV32(t *testing.T) {
	const (
		imageBase = uint64(0x140000000)
		secRVA    = uint32(0x6400)
		targetRVA = uint32(0x16e9c)
	)
	// 48 8B 05 95 0A 01 00 = mov rax, [rip+0x10a95].  The embedded
	// 8B 05 must not be scanned again as a six-byte MOV eax instruction.
	data := []byte{0x48, 0x8B, 0x05, 0x95, 0x0A, 0x01, 0x00}

	refs, found := collectXref64(data, secRVA, testXrefRange(imageBase, targetRVA, targetRVA), 10, 0, nil)
	if found != 1 || len(refs) != 1 {
		t.Fatalf("REX.W MOV xref found %d references, want 1", found)
	}
	if !strings.Contains(refs[0].line, "MOV rax") || strings.Contains(refs[0].line, "MOV eax") {
		t.Fatalf("unexpected REX.W MOV xref: %s", refs[0].line)
	}
}

func TestCollectXref64_RIPRelativeMOV32REXAndStore(t *testing.T) {
	const (
		imageBase = uint64(0x140000000)
		secRVA    = uint32(0x6400)
		targetRVA = uint32(0x16e9c)
	)
	target := testXrefRange(imageBase, targetRVA, targetRVA)
	tests := []struct {
		name string
		data []byte
		want string
	}{
		// 44 8B 05 95 0A 01 00 = mov r8d, [rip+0x10a95]
		{name: "REX r8d load", data: []byte{0x44, 0x8B, 0x05, 0x95, 0x0A, 0x01, 0x00}, want: "MOV r8d"},
		// 89 05 96 0A 01 00 = mov [rip+0x10a96], eax
		{name: "r32 store", data: []byte{0x89, 0x05, 0x96, 0x0A, 0x01, 0x00}, want: "MOV [0x140016e9c], eax"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs, found := collectXref64(tt.data, secRVA, target, 10, 0, nil)
			if found != 1 || len(refs) != 1 {
				t.Fatalf("found %d references, want 1", found)
			}
			if !strings.Contains(refs[0].line, tt.want) {
				t.Fatalf("xref = %s, want %q", refs[0].line, tt.want)
			}
		})
	}
}

func TestCollectXref32_OptionalRange(t *testing.T) {
	const imageBase = uint64(0x400000)
	const targetRVA = uint32(0x2020)
	data := make([]byte, 5)
	data[0] = 0xA1 // MOV EAX,[abs32]
	binary.LittleEndian.PutUint32(data[1:], uint32(imageBase)+targetRVA)

	exact := testXrefRange(imageBase, 0x2000, 0x2000)
	if _, found := collectXref32(data, 0x1000, exact, 10, 0, nil); found != 0 {
		t.Fatalf("exact search unexpectedly matched an interior range address")
	}

	rng := testXrefRange(imageBase, 0x2000, 0x20ff)
	refs, found := collectXref32(data, 0x1000, rng, 10, 0, nil)
	if found != 1 || len(refs) != 1 {
		t.Fatalf("range search found %d references, want 1", found)
	}
	wantVA := imageBase + uint64(targetRVA)
	if !strings.Contains(refs[0].line, fmt.Sprintf("0x%x", wantVA)) {
		t.Fatalf("range result does not report actual target 0x%x: %s", wantVA, refs[0].line)
	}
}

func TestCollectXrefARM64_OptionalRange(t *testing.T) {
	const (
		imageBase = uint64(0x100000000)
		secRVA    = uint32(0x1000)
		targetRVA = uint32(0x2020)
	)
	data := make([]byte, 4)
	imm26 := (targetRVA - secRVA) / 4
	binary.LittleEndian.PutUint32(data, 0x94000000|imm26) // BL targetRVA

	exact := testXrefRange(imageBase, 0x2000, 0x2000)
	if _, found := collectXrefARM64(data, secRVA, exact, 10, 0, nil); found != 0 {
		t.Fatalf("exact search unexpectedly matched an interior range address")
	}

	rng := testXrefRange(imageBase, 0x2000, 0x20ff)
	refs, found := collectXrefARM64(data, secRVA, rng, 10, 0, nil)
	if found != 1 || len(refs) != 1 {
		t.Fatalf("range search found %d references, want 1", found)
	}
	wantVA := imageBase + uint64(targetRVA)
	if !strings.Contains(refs[0].line, fmt.Sprintf("0x%x", wantVA)) {
		t.Fatalf("range result does not report actual target 0x%x: %s", wantVA, refs[0].line)
	}
}

func TestCollectXrefARM32_OptionalRange(t *testing.T) {
	const (
		imageBase = uint64(0x10000)
		secRVA    = uint32(0x1000)
		targetRVA = uint32(0x2020)
	)
	data := make([]byte, 4)
	imm24 := (targetRVA - (secRVA + 8)) / 4
	binary.LittleEndian.PutUint32(data, 0xEB000000|imm24) // BL targetRVA

	exact := testXrefRange(imageBase, 0x2000, 0x2000)
	if _, found := collectXrefARM32(data, secRVA, exact, 10, 0, nil); found != 0 {
		t.Fatalf("exact search unexpectedly matched an interior range address")
	}

	rng := testXrefRange(imageBase, 0x2000, 0x20ff)
	refs, found := collectXrefARM32(data, secRVA, rng, 10, 0, nil)
	if found != 1 || len(refs) != 1 {
		t.Fatalf("range search found %d references, want 1", found)
	}
	wantVA := imageBase + uint64(targetRVA)
	if !strings.Contains(refs[0].line, fmt.Sprintf("0x%x", wantVA)) {
		t.Fatalf("range result does not report actual target 0x%x: %s", wantVA, refs[0].line)
	}
}

func TestXrefTargetRange_InclusiveEndpoints(t *testing.T) {
	rng := testXrefRange(0x140000000, 0x2000, 0x20ff)
	for _, rva := range []int64{0x2000, 0x20ff} {
		if _, ok := rng.containsRVA(rva); !ok {
			t.Fatalf("inclusive range did not contain endpoint 0x%x", rva)
		}
	}
	for _, rva := range []int64{0x1fff, 0x2100, -1, 0x100000000} {
		if _, ok := rng.containsRVA(rva); ok {
			t.Fatalf("range unexpectedly contained RVA 0x%x", rva)
		}
	}
}

func TestXrefTargetEndVAValidation(t *testing.T) {
	tests := []struct {
		name      string
		end       string
		wantError string
	}{
		{name: "invalid", end: "not-an-address", wantError: "invalid target_end_va"},
		{name: "before start", end: "0x1fff", wantError: "must be greater than or equal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := opXref(AnalyzeInput{TargetVA: "0x2000", TargetEndVA: tt.end})
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("opXref error = %v, want substring %q", err, tt.wantError)
			}
		})
	}
}
