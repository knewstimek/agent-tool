package analyze

import (
	"context"
	"debug/elf"
	"debug/pe"
	"fmt"
	"strings"
)

// Only exact PDB/.pdata/ELF symbol ranges are used to attribute interior instructions.
// An unavailable boundary retains entry notes without guessing across functions.
func loadFunctionAnnotations(ctx context.Context, input AnalyzeInput, results []decompileLine) (map[string][]analysisAnnotation, string, error) {
	useful := false
	for _, r := range results {
		if r.Kind == "result" && r.Error == "" {
			useful = true
			break
		}
	}
	if !useful {
		return nil, "", nil
	}
	s, err := openAnnotations(ctx, input, false)
	if err != nil {
		return nil, "", err
	}
	if s == nil {
		return nil, "", nil
	}
	defer s.db.Close()
	var exists bool
	if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM analysis_annotations WHERE binary_sha256=?)", s.hash).Scan(&exists); err != nil {
		return nil, "", err
	}
	if !exists {
		return nil, "", nil
	}
	// Do not call the general xref/call-graph loader here: it sweeps the
	// binary and builds CFGs in the parent. Notes only need exact metadata.
	loc := &xrefLocator{}
	if f, err := pe.Open(input.FilePath); err == nil {
		loc.imageBase = peImageBase(f)
		loc.pdb, _ = loadPDBNameIndex(input.FilePath, input.PDBPath, input.PDBForce, f, loc.imageBase)
		if pd := loadPdata(f, loc.imageBase); pd != nil {
			loc.funcs = pdataFuncTable(pd)
		}
		f.Close()
	}
	clauses := []string{}
	args := []any{s.hash}
	entries := map[string]uint64{}
	ranges := map[string][][2]uint64{}
	missing := false
	elfRanges := map[uint64][2]uint64{}
	if f, err := elf.Open(input.FilePath); err == nil {
		syms, _ := f.Symbols()
		dynamic, _ := f.DynamicSymbols()
		syms = append(syms, dynamic...)
		for _, sym := range syms {
			if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Size > 0 && sym.Size <= ^uint64(0)-sym.Value {
				elfRanges[sym.Value] = [2]uint64{sym.Value, sym.Value + sym.Size}
			}
		}
		f.Close()
	}
	for _, r := range results {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		if r.Kind != "result" || r.Error != "" {
			continue
		}
		key := fmt.Sprintf("%016x", r.Entry)
		if _, ok := entries[key]; ok {
			continue
		}
		entries[key] = r.Entry
		clauses = append(clauses, "va=?")
		args = append(args, key)
		if loc != nil && loc.pdb != nil {
			if p, ok := loc.pdb.procAt(r.Entry); ok && p.start == r.Entry {
				ranges[key] = append(ranges[key], [2]uint64{p.start, p.end})
			}
		}
		if span, ok := elfRanges[r.Entry]; ok {
			ranges[key] = append(ranges[key], span)
		}
		if loc != nil {
			for _, fr := range loc.funcs {
				if fr.exact && loc.imageBase+uint64(fr.entry()) == r.Entry && len(ranges[key]) < 16 {
					ranges[key] = append(ranges[key], [2]uint64{loc.imageBase + uint64(fr.begin), loc.imageBase + uint64(fr.end)})
				} else if fr.exact && loc.imageBase+uint64(fr.entry()) == r.Entry {
					missing = true
				}
			}
		}
		if len(ranges[key]) == 0 {
			missing = true
		}
		for _, span := range ranges[key] {
			clauses = append(clauses, "(kind='instruction' AND va>=? AND va<?)")
			args = append(args, fmt.Sprintf("%016x", span[0]), fmt.Sprintf("%016x", span[1]))
		}
	}
	out := map[string][]analysisAnnotation{}
	if len(clauses) == 0 {
		return out, "", nil
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+s.columns()+" FROM analysis_annotations WHERE binary_sha256=? AND ("+
		strings.Join(clauses, " OR ")+") ORDER BY va,kind,line,id LIMIT 501", args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		a, err := scanAnnotation(rows)
		if err != nil {
			return nil, "", err
		}
		count++
		if count > 500 {
			break
		}
		for key, entry := range entries {
			owned := a.VA == key
			a.scope = "function entry"
			if !owned && a.Kind == "instruction" {
				va, err := parseHexAddr(a.VA)
				if err != nil {
					continue
				}
				for _, span := range ranges[key] {
					if va >= span[0] && va < span[1] {
						owned = true
						a.scope = "exact function range"
						break
					}
				}
			}
			if owned {
				out[fmt.Sprintf("%016x", entry)] = append(out[fmt.Sprintf("%016x", entry)], a)
			}
		}
	}
	notice := ""
	if missing {
		notice = "Some function ranges are unavailable or exceed the 16-range limit; interior notes outside verified ranges are omitted."
	}
	if count > 500 {
		notice += " User annotations limited to 500 records; use annotation_list to read more."
	}
	return out, notice, rows.Err()
}
