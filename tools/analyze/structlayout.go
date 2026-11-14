package analyze

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/knewstimek/gosleigh/pkg/pcode"
)

const (
	defaultStructLength = 64
	maxStructLength     = 512
	// A typed layout covers the whole type, up to this size.
	maxTypedLength = 16384
	maxTypedLines  = 400
)

// opStructLayout dumps a memory region as a structured layout, interpreting
// each pointer-sized slot with symbol/section annotation.
// Useful for inspecting vtables, object layouts, and data structures.
func opStructLayout(input AnalyzeInput) (string, error) {
	vaStr := input.VA
	if vaStr == "" {
		return "", fmt.Errorf("va is required for struct_layout (starting virtual address)")
	}

	startVA, err := parseHexAddr(vaStr)
	if err != nil {
		return "", fmt.Errorf("invalid va: %s", vaStr)
	}

	length := input.Length
	if length <= 0 {
		length = defaultStructLength
	}
	if length > maxStructLength {
		length = maxStructLength
	}

	f, err := pe.Open(input.FilePath)
	if err != nil {
		return "", fmt.Errorf("struct_layout requires a PE file: %w", err)
	}
	defer f.Close()

	imageBase := peImageBase(f)
	is64 := f.FileHeader.Machine == 0x8664 || f.FileHeader.Machine == 0xaa64
	ptrSize := 4
	if is64 {
		ptrSize = 8
	}

	symbols := peSymbolMap(f, imageBase, input.FilePath)
	mergePDBNames(symbols, input.FilePath, input.PDBPath, input.PDBForce, f, imageBase)

	// With debug types the layout is the type's: the global at va (or
	// type_name laid over va), member by member with values. Raw slots
	// remain for memory no type describes.
	out, typed, err := typedLayout(input, f, imageBase, startVA, symbols)
	if typed || err != nil {
		return out, err
	}

	// Read the data block
	data, err := readPEBytesAtVA(f, imageBase, startVA, length)
	if err != nil {
		return "", fmt.Errorf("cannot read data at 0x%x: %w", startVA, err)
	}

	var sb strings.Builder
	sb.WriteString(out) // a note from the typed attempt
	secName := ""
	if startVA >= imageBase && startVA-imageBase <= 0xFFFFFFFF {
		rva := uint32(startVA - imageBase)
		secName = sectionNameForRVA(f, rva)
	}
	if secName != "" {
		sb.WriteString(fmt.Sprintf("Struct layout at 0x%x [%s] (%d-bit, %d bytes):\n\n",
			startVA, secName, ptrSize*8, len(data)))
	} else {
		sb.WriteString(fmt.Sprintf("Struct layout at 0x%x (%d-bit, %d bytes):\n\n",
			startVA, ptrSize*8, len(data)))
	}

	sb.WriteString(fmt.Sprintf("%-8s %-18s %-18s %s\n", "Offset", "Hex", "Value", "Annotation"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	numSlots := len(data) / ptrSize
	for i := 0; i < numSlots; i++ {
		off := i * ptrSize
		slotVA := startVA + uint64(off)

		var val uint64
		var hexStr string
		if ptrSize == 8 {
			val = binary.LittleEndian.Uint64(data[off : off+8])
			hexStr = fmt.Sprintf("%02x %02x %02x %02x %02x %02x %02x %02x",
				data[off], data[off+1], data[off+2], data[off+3],
				data[off+4], data[off+5], data[off+6], data[off+7])
		} else {
			val = uint64(binary.LittleEndian.Uint32(data[off : off+4]))
			hexStr = fmt.Sprintf("%02x %02x %02x %02x",
				data[off], data[off+1], data[off+2], data[off+3])
		}

		ann := classifyValue(f, imageBase, val, symbols)
		sb.WriteString(fmt.Sprintf("+0x%-5x %-18s 0x%-16x %s\n",
			off, hexStr, val, ann))

		// Also show for slot VA if it has a symbol
		if name, ok := symbols[slotVA]; ok {
			sb.WriteString(fmt.Sprintf("         ^ %s\n", name))
		}
	}

	// Show remaining bytes if not aligned to pointer size
	remaining := len(data) % ptrSize
	if remaining > 0 {
		off := numSlots * ptrSize
		var parts []string
		for j := 0; j < remaining; j++ {
			parts = append(parts, fmt.Sprintf("%02x", data[off+j]))
		}
		sb.WriteString(fmt.Sprintf("+0x%-5x %s  (trailing %d bytes)\n",
			off, strings.Join(parts, " "), remaining))
	}

	return sb.String(), nil
}

// typedLayout lays the type of the global at va, or input.TypeName, over
// the image bytes at va. typed is false when no type applies (no debug
// info, no typed global starting there): the caller dumps raw slots after
// out, which may hold a note.
func typedLayout(input AnalyzeInput, f *pe.File, imageBase, va uint64, symbols map[uint64]string) (out string, typed bool, err error) {
	var sb strings.Builder
	applied := false
	err = withDebugInfo(input.FilePath, input.PDBPath, input.PDBForce, func(ds debugSource) error {
		var d *pcode.HostTypeDesc
		label := ""
		if input.TypeName != "" {
			x := ds.typeIndex()
			qs := x.find(input.TypeName, true)
			switch {
			case len(qs) == 0:
				msg := fmt.Sprintf("no struct/class/union named %q in %s", input.TypeName, ds.file())
				if sim := x.similar(input.TypeName, 10); len(sim) > 0 {
					msg += "; similar: " + strings.Join(sim, ", ")
				}
				return fmt.Errorf("%s", msg)
			case len(qs) > 1:
				return fmt.Errorf("%q names %d types; pass a qualified one: %s", input.TypeName, len(qs), strings.Join(qs[:min(len(qs), typeInfoMaxMatches)], ", "))
			}
			d = ds.typeDesc(x.refs[qs[0]].ref)
			label = qs[0] + " laid over"
			if name, start, _, ok := ds.globalDesc(va); ok {
				label += fmt.Sprintf(" (%s+0x%x)", name, va-start)
			}
		} else if name, start, gd, ok := ds.globalDesc(va); ok && gd != nil {
			if start != va {
				fmt.Fprintf(&sb, "Note: 0x%x is inside %s (starts 0x%x, +0x%x); va=0x%x lays out the whole variable.\n\n", va, name, start, va-start, start)
				return nil // raw slots for the middle of a variable
			}
			d, label = gd, name
		}
		if d == nil {
			return nil
		}
		size := int(d.Size)
		if size <= 0 {
			return fmt.Errorf("%s has no size in the debug info", label)
		}
		size = min(size, maxTypedLength)
		data, zeroFrom, err := readImageBytes(f, imageBase, va, size)
		if err != nil {
			return fmt.Errorf("cannot read 0x%x bytes at 0x%x: %v", size, va, err)
		}
		sec := sectionNameForRVA(f, uint32(va-imageBase))
		fmt.Fprintf(&sb, "Typed layout: %s at 0x%x [%s]: %s, 0x%x bytes (%s %s)\n", label, va, sec, cDecl(d, ""), d.Size, ds.kind(), ds.file())
		sb.WriteString("Values are the image's initial data, not a running process (memtool reads live memory).\n")
		if zeroFrom < size {
			fmt.Fprintf(&sb, "Bytes from +0x%x are uninitialized data (zero until the program writes them).\n", zeroFrom)
		}
		if int(d.Size) > size {
			fmt.Fprintf(&sb, "Only the first 0x%x of 0x%x bytes are shown.\n", size, d.Size)
		}
		sb.WriteString("\n")
		lv := layoutWriter{sb: &sb, data: data, annotate: func(v uint64) string { return classifyValue(f, imageBase, v, symbols) }}
		if d.Meta == "struct" || d.Meta == "union" {
			lv.members(d, ds, 0, "", 0)
		} else {
			lv.member(d, ds, 0, label, 0, 0, 0)
		}
		if lv.lines >= maxTypedLines {
			fmt.Fprintf(&sb, "... stopped at %d lines; pass va of a member (and type_name) to see the rest\n", maxTypedLines)
		}
		applied = true
		return nil
	})
	if err != nil {
		if input.TypeName == "" && errors.Is(err, errNoDebugInfo) {
			return "", false, nil // no debug info: raw slots
		}
		return "", false, err
	}
	return sb.String(), applied, nil
}

// readImageBytes reads size bytes at va as the loaded image holds them:
// the part of a section beyond its raw data (.bss) reads as zero; zeroFrom
// is the first such offset (size when none).
func readImageBytes(f *pe.File, imageBase, va uint64, size int) ([]byte, int, error) {
	if va < imageBase || va-imageBase > 0xFFFFFFFF {
		return nil, 0, fmt.Errorf("0x%x is outside the image", va)
	}
	rva := uint32(va - imageBase)
	for _, s := range f.Sections {
		end := s.VirtualAddress + max(s.VirtualSize, s.Size)
		if rva < s.VirtualAddress || rva >= end {
			continue
		}
		out := make([]byte, min(size, int(end-rva)))
		raw, err := s.Data()
		if err != nil {
			return nil, 0, err
		}
		off := int(rva - s.VirtualAddress)
		zeroFrom := len(out)
		if off < len(raw) {
			if n := copy(out, raw[off:]); n < len(out) {
				zeroFrom = n
			}
		} else {
			zeroFrom = 0
		}
		return out, zeroFrom, nil
	}
	return nil, 0, fmt.Errorf("no section holds RVA 0x%x", rva)
}

// layoutWriter prints members with their values.
type layoutWriter struct {
	sb       *strings.Builder
	data     []byte
	annotate func(uint64) string
	lines    int
}

func (w *layoutWriter) line(format string, args ...any) {
	if w.lines < maxTypedLines {
		fmt.Fprintf(w.sb, format, args...)
	}
	w.lines++
}

// members prints the fields of a structure or union at base, nested
// structures flattened into dotted paths.
func (w *layoutWriter) members(d *pcode.HostTypeDesc, ds debugSource, base int, path string, depth int) {
	for _, f := range d.Fields {
		w.member(f.Type, ds, base+int(f.Offset), path+f.Name, f.BitOffset, f.BitSize, depth)
	}
	if ov := ds.overlapsOf(d); len(ov) > 0 {
		names := make([]string, len(ov))
		for i, f := range ov {
			names[i] = fmt.Sprintf("%s%s (+0x%x)", path, f.Name, base+int(f.Offset))
		}
		w.line("         (overlapping members not shown: %s)\n", strings.Join(names, ", "))
	}
}

func (w *layoutWriter) member(t *pcode.HostTypeDesc, ds debugSource, off int, name string, bitOff, bitSize int32, depth int) {
	if w.lines >= maxTypedLines {
		return
	}
	if off >= len(w.data) {
		return
	}
	aggregate := t != nil && (t.Meta == "struct" || t.Meta == "union" || t.Meta == "array")
	switch {
	case t == nil:
		w.line("+0x%04x %s = ?\n", off, name)
	case aggregate && allZero(w.data, off, int(t.Size)):
		// Zero-filled (uninitialized) aggregates are one line, not one
		// per member: an array of structures would bury the data.
		w.line("+0x%04x %s = {0}\n", off, cDecl(t, name))
	case bitSize > 0:
		raw, _ := readLE(w.data, off, int(t.Size))
		v := raw >> uint(bitOff) & (1<<uint(bitSize) - 1)
		val := fmt.Sprintf("%d", v)
		if t.Meta == "int" && v>>(uint(bitSize)-1) == 1 {
			val = fmt.Sprintf("%d", int64(v)-int64(1)<<uint(bitSize))
		}
		w.line("+0x%04x %s : %d = %s // bits %d..%d\n", off, cDecl(t, name), bitSize, val, bitOff, bitOff+bitSize-1)
	case (t.Meta == "struct" || t.Meta == "union") && depth < 4:
		w.line("+0x%04x %s:\n", off, cDecl(t, name))
		w.members(t, ds, off, name+".", depth+1)
	case t.Meta == "array" && t.Elem != nil && t.Count > 0:
		el := t.Elem
		if el.Char && el.Size == 1 {
			end := min(off+int(t.Count), len(w.data))
			w.line("+0x%04x %s = %q\n", off, cDecl(t, name), cString(w.data[off:end]))
			return
		}
		if (el.Meta == "struct" || el.Meta == "union") && depth < 4 {
			for i := 0; i < int(t.Count) && i < 16; i++ {
				w.member(el, ds, off+i*int(el.Size), fmt.Sprintf("%s[%d]", name, i), 0, 0, depth+1)
			}
			if t.Count > 16 {
				w.line("         %s: %d more elements\n", name, t.Count-16)
			}
			return
		}
		vals := make([]string, 0, min(int(t.Count), 16)+1)
		for i := 0; i < int(t.Count) && i < 16; i++ {
			vals = append(vals, w.value(el, off+i*int(el.Size)))
		}
		if t.Count > 16 {
			vals = append(vals, fmt.Sprintf("... %d more", t.Count-16))
		}
		w.line("+0x%04x %s = {%s}\n", off, cDecl(t, name), strings.Join(vals, ", "))
	default:
		w.line("+0x%04x %s = %s\n", off, cDecl(t, name), w.value(t, off))
	}
}

// value formats the scalar of type t at off.
func (w *layoutWriter) value(t *pcode.HostTypeDesc, off int) string {
	size := int(t.Size)
	raw, ok := readLE(w.data, off, size)
	if !ok {
		return "<past the shown bytes>"
	}
	if size > 8 {
		return fmt.Sprintf("% x", w.data[off:off+size])
	}
	switch t.Meta {
	case "ptr":
		if ann := w.annotate(raw); ann != "" {
			return fmt.Sprintf("0x%x %s", raw, ann)
		}
		return fmt.Sprintf("0x%x", raw)
	case "float":
		switch size {
		case 4:
			return fmt.Sprintf("%g", math.Float32frombits(uint32(raw)))
		case 8:
			return fmt.Sprintf("%g", math.Float64frombits(raw))
		}
	case "bool":
		return fmt.Sprintf("%t", raw != 0)
	case "enum_int", "enum_uint":
		if n, ok := t.EnumValues[raw]; ok {
			return fmt.Sprintf("%s (%s)", n, enumValue(raw, t))
		}
		return enumValue(raw, t)
	case "int":
		v := int64(raw<<(64-8*uint(size))) >> (64 - 8*uint(size))
		if t.Char && size == 1 && v >= 0x20 && v < 0x7f {
			return fmt.Sprintf("%d '%c'", v, rune(v))
		}
		if v >= 10 || v <= -10 {
			return fmt.Sprintf("%d (0x%x)", v, raw)
		}
		return fmt.Sprintf("%d", v)
	}
	if raw >= 10 {
		return fmt.Sprintf("%d (0x%x)", raw, raw)
	}
	return fmt.Sprintf("%d", raw)
}

func readLE(b []byte, off, size int) (uint64, bool) {
	if size <= 0 || off < 0 || off+size > len(b) {
		return 0, false
	}
	var v uint64
	for i := min(size, 8) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[off+i])
	}
	return v, true
}

func allZero(b []byte, off, size int) bool {
	if off+size > len(b) {
		size = len(b) - off
	}
	for _, c := range b[off : off+size] {
		if c != 0 {
			return false
		}
	}
	return size > 0
}

// cString is b up to its first NUL.
func cString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// classifyValue interprets a pointer-sized value: symbol, section classification, or null.
func classifyValue(f *pe.File, imageBase, val uint64, symbols map[uint64]string) string {
	if val == 0 {
		return "[null]"
	}

	// Check symbol map first
	if name, ok := symbols[val]; ok {
		return name
	}

	// Check if it points to a valid section
	if val >= imageBase && val-imageBase <= 0xFFFFFFFF {
		rva := uint32(val - imageBase)
		for _, s := range f.Sections {
			if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
				// Classify by section characteristics
				isExec := s.Characteristics&0x20000000 != 0
				isWrite := s.Characteristics&0x80000000 != 0
				if isExec {
					return fmt.Sprintf("[code] %s", s.Name)
				}
				if isWrite {
					return fmt.Sprintf("[data] %s", s.Name)
				}
				return fmt.Sprintf("[rdata] %s", s.Name)
			}
		}
	}

	// Not a valid section pointer -- could be a scalar value
	return ""
}
