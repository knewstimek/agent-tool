package analyze

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	synthImageBase = 0x140000000
	synthSecRVA    = 0x1000
)

// syntheticPE builds a minimal PE32+ image with one data section at RVA
// 0x1000 and one data directory pointing at its start; fill writes the
// section's content.
func syntheticPE(machine uint16, dirIndex int, dirSize uint32, fill func(sec []byte)) []byte {
	const (
		secRaw  = 0x200
		secSize = 0x400
	)
	img := make([]byte, secRaw+secSize)
	le := binary.LittleEndian

	// DOS header -> PE signature at 0x80.
	copy(img, "MZ")
	le.PutUint32(img[0x3c:], 0x80)
	copy(img[0x80:], "PE\x00\x00")
	coff := img[0x84:]
	le.PutUint16(coff[0:], machine)
	le.PutUint16(coff[2:], 1)     // sections
	le.PutUint16(coff[16:], 240)  // optional header size
	le.PutUint16(coff[18:], 0x22) // executable, large address aware

	opt := img[0x98:]
	le.PutUint16(opt[0:], 0x20b) // PE32+
	le.PutUint64(opt[24:], synthImageBase)
	le.PutUint32(opt[32:], 0x1000)             // section alignment
	le.PutUint32(opt[36:], 0x200)              // file alignment
	le.PutUint32(opt[56:], synthSecRVA+0x1000) // image size
	le.PutUint32(opt[60:], secRaw)             // headers size
	le.PutUint32(opt[108:], 16)                // data directories
	le.PutUint32(opt[112+dirIndex*8:], synthSecRVA)
	le.PutUint32(opt[112+dirIndex*8+4:], dirSize)

	sh := img[0x98+240:]
	copy(sh, ".rdata")
	le.PutUint32(sh[8:], secSize)      // virtual size
	le.PutUint32(sh[12:], synthSecRVA) // virtual address
	le.PutUint32(sh[16:], secSize)     // raw size
	le.PutUint32(sh[20:], secRaw)      // raw pointer
	le.PutUint32(sh[36:], 0x40000040)

	fill(img[secRaw:])
	return img
}

// delayImportPE is an image whose only data directory is a delay-load
// directory: delay.dll importing DelayFn by name and ordinal 7.
func delayImportPE(t *testing.T) *pe.File {
	t.Helper()
	le := binary.LittleEndian
	img := syntheticPE(0x8664, 13, 2*32, func(sec []byte) {
		// ImgDelayDescr: attributes (RVA form), DLL name, module handle, IAT,
		// import name table. The next descriptor stays zero and ends the list.
		le.PutUint32(sec[0:], 1)
		le.PutUint32(sec[4:], synthSecRVA+0x100)
		le.PutUint32(sec[8:], synthSecRVA+0x200)
		le.PutUint32(sec[12:], synthSecRVA+0x180)
		le.PutUint32(sec[16:], synthSecRVA+0x140)
		copy(sec[0x100:], "delay.dll\x00")
		// Import name table: by name, by ordinal, terminator.
		le.PutUint64(sec[0x140:], synthSecRVA+0x160)
		le.PutUint64(sec[0x148:], 1<<63|7)
		copy(sec[0x162:], "DelayFn\x00") // after the 2-byte hint
		// IAT before binding: pointers to the delay-load thunks, not names.
		le.PutUint64(sec[0x180:], synthImageBase+0x2000)
		le.PutUint64(sec[0x188:], synthImageBase+0x2010)
	})
	f, err := pe.NewFile(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("synthetic PE does not parse: %v", err)
	}
	return f
}

// exportingDLL is a DLL image exporting ordinals 5..7, of which only 7 has a
// name.
func exportingDLL(machine uint16, name string) []byte {
	le := binary.LittleEndian
	return syntheticPE(machine, 0, 40, func(sec []byte) {
		// IMAGE_EXPORT_DIRECTORY
		le.PutUint32(sec[12:], synthSecRVA+0x100) // DLL name
		le.PutUint32(sec[16:], 5)                 // ordinal base
		le.PutUint32(sec[20:], 3)                 // functions
		le.PutUint32(sec[24:], 1)                 // names
		le.PutUint32(sec[28:], synthSecRVA+0x140) // function RVAs
		le.PutUint32(sec[32:], synthSecRVA+0x160) // name RVAs
		le.PutUint32(sec[36:], synthSecRVA+0x180) // name ordinals
		copy(sec[0x100:], "delay.dll\x00")
		le.PutUint32(sec[0x140:], 0x1300)
		le.PutUint32(sec[0x144:], 0x1310)
		le.PutUint32(sec[0x148:], 0x1320)
		le.PutUint32(sec[0x160:], synthSecRVA+0x1a0)
		le.PutUint16(sec[0x180:], 2) // index of ordinal 7
		copy(sec[0x1a0:], name+"\x00")
	})
}

func TestDelayLoadImportsNameTheirSlots(t *testing.T) {
	f := delayImportPE(t)
	base := peImageBase(f)
	imports := peImports(f, base, "")

	byName := imports[base+0x1180]
	if byName.name != "DelayFn" || byName.dll != "delay.dll" || !byName.delay {
		t.Errorf("slot 0x1180 = %+v, want DelayFn from delay.dll (delay)", byName)
	}
	byOrdinal := imports[base+0x1188]
	if byOrdinal.display() != "Ordinal_7" || !byOrdinal.delay {
		t.Errorf("slot 0x1188 = %+v, want Ordinal_7 (delay)", byOrdinal)
	}
	if len(imports) != 2 {
		t.Errorf("got %d imports, want 2: %+v", len(imports), imports)
	}

	// The same slots reach disassembly annotation, name resolution and the
	// decompiler host through the symbol map.
	if got := peSymbolMap(f, base, "")[base+0x1180]; got != "DelayFn" {
		t.Errorf("symbol map names the slot %q, want DelayFn", got)
	}

	var sb strings.Builder
	parseDelayImports(f, &sb, "")
	out := sb.String()
	for _, want := range []string{"Delay Imports (1 DLLs, 2 functions", "delay.dll (2)", "0x140001180  DelayFn", "0x140001188  Ordinal_7"} {
		if !strings.Contains(out, want) {
			t.Errorf("pe_info delay listing lacks %q:\n%s", want, out)
		}
	}
}

// An import by ordinal takes the name the DLL beside the binary exports for
// that ordinal; a DLL built for another machine type is not that DLL.
func TestOrdinalImportNamedFromTheDLL(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "app.exe")
	dll := filepath.Join(dir, "delay.dll")
	f := delayImportPE(t)
	base := peImageBase(f)

	if got := peImports(f, base, bin)[base+0x1188].display(); got != "Ordinal_7" {
		t.Errorf("without the DLL on disk the import is %q, want Ordinal_7", got)
	}

	// The lookup above cached "no DLL at this path"; a new directory stands
	// for a binary whose DLL is present.
	dir = t.TempDir()
	bin, dll = filepath.Join(dir, "app.exe"), filepath.Join(dir, "delay.dll")
	if err := os.WriteFile(dll, exportingDLL(0x14c, "WrongArch"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := importOrdinalName(bin, 0x8664, "delay.dll", 7); got != "" {
		t.Errorf("a 32-bit DLL named a 64-bit binary's import: %q", got)
	}

	dir = t.TempDir()
	bin, dll = filepath.Join(dir, "app.exe"), filepath.Join(dir, "delay.dll")
	if err := os.WriteFile(dll, exportingDLL(0x8664, "NamedFn"), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := peImports(f, base, bin)[base+0x1188]
	if ref.display() != "NamedFn" || ref.ordinal != 7 {
		t.Errorf("ordinal import = %+v, want NamedFn (ordinal 7)", ref)
	}
	if got := importOrdinalName(bin, 0x8664, "DELAY", 6); got != "" {
		t.Errorf("an ordinal exported without a name resolved to %q", got)
	}
	// A DLL name is data from the analyzed binary, not a path to follow.
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := importOrdinalName(filepath.Join(sub, "app.exe"), 0x8664, `..\delay.dll`, 7); got != "" {
		t.Errorf("a DLL name with a path reached %q outside the binary's directory", got)
	}
}
