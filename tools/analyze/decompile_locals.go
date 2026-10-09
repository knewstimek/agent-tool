package analyze

import (
	"encoding/binary"
	"strings"

	"github.com/knewstimek/gopdb"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// pdbLocalNames applies debug-info local variable names and types. Ghidra's PDB analysis
// leaves an optimized program's locals to the decompiler; this goes further
// for readability, and the golden measurement turns it off to compare.
var pdbLocalNames = true

// pdbLocalTypes applies their types too (type-locked, as Ghidra does for a
// typed local symbol).
var pdbLocalTypes = true

// CodeView registers used as frame bases (cvconst.h CV_HREG_e).
const (
	cvRegESP = 21
	cvRegEBP = 22
	cvRegRBP = 334
	cvRegRSP = 335
)

// Frame base encodings in S_FRAMEPROC flags (bits 14-15 locals, 16-17
// parameters): 1 is the stack pointer, 2 the frame pointer.
const (
	frameBaseSP = 1
	frameBaseBP = 2
)

const symDefRangeFramePointerRelFullScope = 0x1144

// stackVar is a named stack variable. typ is nil when its type is not
// expressible.
type stackVar struct {
	name string
	typ  *pcode.HostTypeDesc
}

// frameBase locates a function's frame pointer: where it points relative to
// the stack pointer at entry, when the binary records it (x64 unwind info).
type frameBase struct {
	is64  bool
	rsp   int64 // x64: RSP after the prologue, when rspOK
	rspOK bool
	fp    int64 // x64: where RBP points, when fpOK
	fpOK  bool
}

// pdbLocals maps the stack offsets of a procedure's named local variables
// (relative to the stack pointer at entry, the decompiler's stack space:
// the return address at 0, locals below it) to their names and types.
// Parameters come with the prototype and are left out.
//
// Offset translation, checked against MSVC output for both architectures:
//   - x64 RSP-relative (S_REGREL32 RSP, or SP-based frame records): the RSP
//     after the prologue, from the image's unwind codes (S_FRAMEPROC leaves
//     pushes out of SaveRegsSize); FrameSize + SaveRegsSize below the entry
//     RSP when there are none.
//   - x64 RBP-relative: where RBP points depends on the prologue, which the
//     PDB does not record; the unwind codes do (UWOP_SET_FPREG).
//   - x86 ESP-relative: already relative to the entry ESP (the FPO virtual
//     frame).
//   - x86 EBP-relative (S_BPREL32, S_REGREL32 EBP, BP-based frames): EBP is
//     the entry ESP minus the saved EBP.
//
// nParams is the prototype's parameter count, this included: MSVC records
// the parameters first among the S_REGREL32/S_BPREL32 records, with nothing
// marking them as parameters, and an optimized one can point into the frame.
func pdbLocals(p *pdb.Procedure, nParams int, fb frameBase, typeOf func(pdb.TypeIndex) *pcode.HostTypeDesc) map[int64]stackVar {
	var frame *pdb.FrameProc
	for _, s := range p.Locals {
		if f, ok := s.(*pdb.FrameProc); ok {
			frame = f
			break
		}
	}
	spOffset := func(off int64) (int64, bool) {
		if fb.is64 {
			if fb.rspOK {
				return off + fb.rsp, true
			}
			if frame == nil {
				return 0, false
			}
			return off - int64(frame.FrameSize) - int64(frame.SaveRegsSize), true
		}
		return off, true
	}
	bpOffset := func(off int64) (int64, bool) {
		if fb.is64 {
			return off + fb.fp, fb.fpOK
		}
		return off - 4, true
	}
	out := map[int64]stackVar{}
	add := func(name string, ti pdb.TypeIndex, off int64, ok bool) {
		if !ok || off >= 0 || name == "" || strings.HasPrefix(name, "$") || strings.HasPrefix(name, "__$") {
			return
		}
		if _, dup := out[off]; !dup {
			out[off] = stackVar{name: name, typ: typeOf(ti)}
		}
	}
	var pending *pdb.Local // an S_LOCAL whose location records follow
	param := func() bool { // the next register-relative record is a parameter
		nParams--
		return nParams >= 0
	}
	for _, s := range p.Locals {
		switch v := s.(type) {
		case *pdb.Local:
			pending = v
			if v.Flags&pdb.LocalIsParam != 0 {
				pending = nil
			}
		case *pdb.RegRel:
			pending = nil
			if param() {
				continue
			}
			switch {
			case fb.is64 && v.Register == cvRegRSP, !fb.is64 && v.Register == cvRegESP:
				off, ok := spOffset(int64(v.Offset))
				add(v.Name, v.Type, off, ok)
			case fb.is64 && v.Register == cvRegRBP, !fb.is64 && v.Register == cvRegEBP:
				off, ok := bpOffset(int64(v.Offset))
				add(v.Name, v.Type, off, ok)
			}
		case *pdb.BPRel:
			pending = nil
			if param() {
				continue
			}
			off, ok := bpOffset(int64(v.Offset))
			add(v.Name, v.Type, off, ok)
		case *pdb.RawSymbol:
			if pending == nil || v.K != symDefRangeFramePointerRelFullScope || len(v.Data) < 4 || frame == nil {
				continue
			}
			rel := int64(int32(binary.LittleEndian.Uint32(v.Data)))
			switch frame.Flags >> 14 & 3 {
			case frameBaseSP:
				off, ok := spOffset(rel)
				add(pending.Name, pending.Type, off, ok)
			case frameBaseBP:
				off, ok := bpOffset(rel)
				add(pending.Name, pending.Type, off, ok)
			}
			pending = nil
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
