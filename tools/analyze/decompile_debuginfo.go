package analyze

import (
	"github.com/knewstimek/gopdb"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// debugSource is what a debug-information format (PDB, DWARF) gives the
// decompile host. Names are qualified, as recorded (see ghidraName).
type debugSource interface {
	kind() string // "PDB" or "DWARF", for the output header
	file() string
	functionNames() map[uint64]string
	prototype(va uint64) *pcode.HostFunction
	// dataAt is the global variable whose storage contains va.
	dataAt(va uint64) (name string, start uint64, t pcode.Datatype, ok bool)
	// locals maps entry-relative stack offsets of a function's local
	// variables to their names and types (nil when none).
	locals(va uint64, fb frameBase) map[int64]stackVar
	noReturn() []uint64
}

func (pi *pdbInfo) kind() string { return "PDB" }
func (pi *pdbInfo) file() string { return pi.path }

func (pi *pdbInfo) functionNames() map[uint64]string {
	names := make(map[uint64]string, len(pi.funcs))
	for va, f := range pi.funcs {
		names[va] = f.name
	}
	return names
}

func (pi *pdbInfo) dataAt(va uint64) (string, uint64, pcode.Datatype, bool) {
	d, ok := pi.globalAt(va)
	if !ok {
		return "", 0, nil, false
	}
	t := pi.types.datatype(d.typ)
	return d.name, d.va, t, t != nil
}

func (pi *pdbInfo) locals(va uint64, fb frameBase) map[int64]stackVar {
	f := pi.funcs[va]
	if f == nil || f.proc == nil {
		return nil
	}
	return pdbLocals(f.proc, pi.types.paramCount(f.proc.Type), fb, func(ti pdb.TypeIndex) *pcode.HostTypeDesc {
		if pi.types == nil {
			return nil
		}
		return pi.types.desc(ti)
	})
}

func (pi *pdbInfo) noReturn() []uint64 {
	var out []uint64
	for va, f := range pi.funcs {
		if f.proc != nil && f.proc.Flags&pdb.ProcNoReturn != 0 {
			out = append(out, va)
		}
	}
	return out
}
