package analyze

import (
	"reflect"
	"testing"

	"github.com/knewstimek/gopdb"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// unwindIndex serves one function's UNWIND_INFO at RVA 0x2000 for a
// function at RVA 0x1000.
func unwindIndex(info []byte) *pdataIndex {
	return &pdataIndex{
		unwind: map[uint32]uint32{0x1000: 0x2000},
		read: func(rva uint32, n int) []byte {
			off := int(rva) - 0x2000
			if off < 0 || off+n > len(info) {
				return nil
			}
			return info[off : off+n]
		},
	}
}

func TestPrologueFrame(t *testing.T) {
	// push rbp; push r12; push r13; push r14; push r15; sub rsp, 0x50;
	// lea rbp, [rsp+0x30] -- codes in reverse prologue order.
	withFP := []byte{
		0x01, 0x13, 7, 0x35, // version 1, prologue 0x13, 7 codes, RBP + 3*16
		0x13, 0x03, // SET_FPREG
		0x0e, 0x92, // ALLOC_SMALL (9+1)*8 = 0x50
		0x0a, 0xf0, // PUSH r15
		0x08, 0xe0, // PUSH r14
		0x06, 0xd0, // PUSH r13
		0x04, 0xc0, // PUSH r12
		0x02, 0x50, // PUSH rbp
	}
	fr, ok := unwindIndex(withFP).frame(0x140000000, 0x140001000)
	if want := (prologueFrame{rsp: -120, fp: -72, fpReg: 5}); !ok || fr != want {
		t.Errorf("frame = %+v, %v; want %+v", fr, ok, want)
	}

	// Three pushes that S_FRAMEPROC leaves out of SaveRegsSize, a large
	// allocation and register saves that do not move RSP.
	noFP := []byte{
		0x01, 0x20, 9, 0x00,
		0x1e, 0x64, 0x14, 0x00, // SAVE_NONVOL rsi, [rsp+0xa0]
		0x1a, 0x34, 0x12, 0x00, // SAVE_NONVOL rbx
		0x0e, 0x01, 0x0e, 0x00, // ALLOC_LARGE 0x0e*8 = 0x70
		0x07, 0xe0, // PUSH r14
		0x05, 0x70, // PUSH rdi
		0x04, 0x50, // PUSH rbp
		0x00, 0x00, // padding to an even count
	}
	fr, ok = unwindIndex(noFP).frame(0x140000000, 0x140001000)
	if want := (prologueFrame{rsp: -0x88}); !ok || fr != want {
		t.Errorf("frame = %+v, %v; want %+v", fr, ok, want)
	}

	// Chained info is a split-off part of a function, not an entry.
	chained := append([]byte{0x21}, withFP[1:]...)
	if _, ok := unwindIndex(chained).frame(0x140000000, 0x140001000); ok {
		t.Error("chained unwind info taken as a function's prologue")
	}
}

// MSVC records parameters first among the register-relative records with
// nothing marking them; an optimized one can point into the frame.
func TestPDBLocalsSkipParameters(t *testing.T) {
	proc := &pdb.Procedure{Locals: []pdb.Symbol{
		&pdb.FrameProc{FrameSize: 0x20},
		&pdb.RegRel{Name: "this", Register: cvRegRSP, Offset: 0x30},
		&pdb.RegRel{Name: "bAllowShrinking", Register: cvRegRSP, Offset: 0},
		&pdb.RegRel{Name: "Diff", Register: cvRegRSP, Offset: 8},
	}}
	intDesc := &pcode.HostTypeDesc{Meta: "int", Size: 4, Name: "int"}
	got := pdbLocals(proc, 2, frameBase{is64: true, rsp: -0x28, rspOK: true},
		func(pdb.TypeIndex) *pcode.HostTypeDesc { return intDesc })
	want := map[int64]stackVar{-0x20: {name: "Diff", typ: intDesc}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("locals = %v; want %v", got, want)
	}
}

func TestGoResultSlot(t *testing.T) {
	i4 := pcode.ResolveHostType(&pcode.HostTypeDesc{Meta: "int", Size: 4, Name: "int"})
	b1 := pcode.ResolveHostType(&pcode.HostTypeDesc{Meta: "uint", Size: 1, Name: "uint8"})
	params := func(ts ...pcode.Datatype) []pcode.HostParam {
		var ps []pcode.HostParam
		for _, t := range ts {
			ps = append(ps, pcode.HostParam{Type: t, Size: t.Size()})
		}
		return ps
	}
	for _, c := range []struct {
		params []pcode.HostParam
		want   int32
	}{
		{params(i4, i4), 12}, // a at 4, b at 8, result at 12
		{params(b1), 8},      // the results section is pointer-aligned
		{params(b1, b1), 8},
		{nil, 4},
	} {
		if got := goResultSlot(c.params, i4, 4); got != c.want {
			t.Errorf("goResultSlot(%d params) = %d; want %d", len(c.params), got, c.want)
		}
	}
}
