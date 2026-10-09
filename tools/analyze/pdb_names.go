package analyze

import (
	"debug/pe"
	"fmt"
	"os"
	"sort"
	"sync"
)

// pdbNameIndex is what the address-oriented operations (disassemble,
// call_graph, xref, follow_ptr, struct_layout, function_at) take from a
// matching PDB: names for functions and global data, and procedure extents.
type pdbNameIndex struct {
	path   string
	names  map[uint64]string // VA -> qualified name
	ranges []pdbRange        // procedures, sorted by start
}

type pdbRange struct {
	start, end uint64
	name       string
}

// One index is cached: a large PDB takes about a second to read and an
// agent usually works on one binary at a time; keeping more would hold tens
// of megabytes per binary in a long-lived server.
var pdbNameCache struct {
	mu   sync.Mutex
	key  string
	idx  *pdbNameIndex
	note string
}

// loadPDBNameIndex returns the PDB name index for the PE image at exePath
// (nil when there is no matching PDB, with a note saying why when one was
// expected). pdbPath overrides the PDB location; "none" disables it.
func loadPDBNameIndex(exePath, pdbPath string, f *pe.File, imageBase uint64) (*pdbNameIndex, string) {
	if pdbPath == "none" {
		return nil, ""
	}
	st, err := os.Stat(exePath)
	if err != nil {
		return nil, ""
	}
	key := fmt.Sprintf("%s|%d|%d|%s", exePath, st.Size(), st.ModTime().UnixNano(), pdbPath)
	pdbNameCache.mu.Lock()
	defer pdbNameCache.mu.Unlock()
	if pdbNameCache.key == key {
		return pdbNameCache.idx, pdbNameCache.note
	}
	_, is64 := f.OptionalHeader.(*pe.OptionalHeader64)
	pi, note := openPDBInfo(exePath, pdbPath, f, imageBase, is64)
	var idx *pdbNameIndex
	if pi != nil {
		idx = &pdbNameIndex{path: pi.path, names: make(map[uint64]string, len(pi.funcs)+len(pi.data))}
		for va, fn := range pi.funcs {
			idx.names[va] = fn.name
			if fn.proc != nil && fn.proc.Length > 0 {
				idx.ranges = append(idx.ranges, pdbRange{start: va, end: va + uint64(fn.proc.Length), name: fn.name})
			}
		}
		for _, d := range pi.data {
			if _, ok := idx.names[d.va]; !ok {
				idx.names[d.va] = d.name
			}
		}
		sort.Slice(idx.ranges, func(i, j int) bool { return idx.ranges[i].start < idx.ranges[j].start })
	}
	pdbNameCache.key, pdbNameCache.idx, pdbNameCache.note = key, idx, note
	return idx, note
}

// mergePDBNames adds PDB names for addresses the file's own symbols do not
// name; the file's names (exports, import slots) keep priority.
func mergePDBNames(syms map[uint64]string, exePath, pdbPath string, f *pe.File, imageBase uint64) {
	idx, _ := loadPDBNameIndex(exePath, pdbPath, f, imageBase)
	if idx == nil {
		return
	}
	for va, n := range idx.names {
		if _, ok := syms[va]; !ok {
			syms[va] = n
		}
	}
}

// procAt returns the PDB procedure whose code contains va.
func (idx *pdbNameIndex) procAt(va uint64) (pdbRange, bool) {
	i := sort.Search(len(idx.ranges), func(i int) bool { return idx.ranges[i].start > va })
	if i == 0 {
		return pdbRange{}, false
	}
	r := idx.ranges[i-1]
	return r, va < r.end
}
