package analyze

import (
	"encoding/binary"
	"strings"

	"github.com/knewstimek/gopdb"
)

// pdbLocalNames applies PDB local variable names. Ghidra's PDB analysis
// leaves an optimized program's locals to the decompiler; this goes further
// for readability, and the golden measurement turns it off to compare.
var pdbLocalNames = true

// CodeView registers used as frame bases (cvconst.h CV_HREG_e).
const (
	cvRegESP = 21
	cvRegEBP = 22
	cvRegRSP = 335
)

// Frame base encodings in S_FRAMEPROC flags (bits 14-15 locals, 16-17
// parameters): 1 is the stack pointer, 2 the frame pointer.
const (
	frameBaseSP = 1
	frameBaseBP = 2
)

const symDefRangeFramePointerRelFullScope = 0x1144

// localNames maps the stack offsets of a procedure's named local variables
// (relative to the stack pointer at entry, the decompiler's stack space:
// the return address at 0, locals below it) to their names. Parameters come
// with the prototype and are left out.
//
// Offset translation, checked against MSVC output for both architectures:
//   - x64 RSP-relative (S_REGREL32 RSP, or SP-based frame records): the RSP
//     after the prologue, FrameSize + SaveRegsSize below the entry RSP.
//   - x86 ESP-relative: already relative to the entry ESP (the FPO virtual
//     frame).
//   - x86 EBP-relative (S_BPREL32, S_REGREL32 EBP, BP-based frames): EBP is
//     the entry ESP minus the saved EBP.
//
// x64 RBP-based frames are skipped: where RBP points depends on the
// prologue, which the PDB does not record.
func localNames(p *pdb.Procedure, is64 bool) map[int64]string {
	var frame *pdb.FrameProc
	for _, s := range p.Locals {
		if f, ok := s.(*pdb.FrameProc); ok {
			frame = f
			break
		}
	}
	spOffset := func(off int64) (int64, bool) {
		if is64 {
			if frame == nil {
				return 0, false
			}
			return off - int64(frame.FrameSize) - int64(frame.SaveRegsSize), true
		}
		return off, true
	}
	bpOffset := func(off int64) (int64, bool) {
		if is64 {
			return 0, false
		}
		return off - 4, true
	}
	out := map[int64]string{}
	add := func(name string, off int64, ok bool) {
		if !ok || off >= 0 || name == "" || strings.HasPrefix(name, "$") || strings.HasPrefix(name, "__$") {
			return
		}
		if _, dup := out[off]; !dup {
			out[off] = name
		}
	}
	var pending *pdb.Local // an S_LOCAL whose location records follow
	for _, s := range p.Locals {
		switch v := s.(type) {
		case *pdb.Local:
			pending = v
			if v.Flags&pdb.LocalIsParam != 0 {
				pending = nil
			}
		case *pdb.RegRel:
			pending = nil
			switch {
			case is64 && v.Register == cvRegRSP, !is64 && v.Register == cvRegESP:
				off, ok := spOffset(int64(v.Offset))
				add(v.Name, off, ok)
			case !is64 && v.Register == cvRegEBP:
				off, ok := bpOffset(int64(v.Offset))
				add(v.Name, off, ok)
			}
		case *pdb.BPRel:
			pending = nil
			off, ok := bpOffset(int64(v.Offset))
			add(v.Name, off, ok)
		case *pdb.RawSymbol:
			if pending == nil || v.K != symDefRangeFramePointerRelFullScope || len(v.Data) < 4 || frame == nil {
				continue
			}
			rel := int64(int32(binary.LittleEndian.Uint32(v.Data)))
			switch frame.Flags >> 14 & 3 {
			case frameBaseSP:
				off, ok := spOffset(rel)
				add(pending.Name, off, ok)
			case frameBaseBP:
				off, ok := bpOffset(rel)
				add(pending.Name, off, ok)
			}
			pending = nil
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
