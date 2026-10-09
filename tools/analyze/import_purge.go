package analyze

import (
	"debug/pe"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/arch/x86/x86asm"
)

// x86 stdcall imports pop their own arguments (ret N), which the value
// tracer must model to keep the stack pointer in step. The import table
// names the function but not its argument size, so the size is read from
// the DLL itself: the export's code is walked to its ret N, following
// forwarders (kernel32 -> kernelbase) and API set stubs. Ghidra gets the
// same number from its Windows API type archives; reading the real DLL
// needs no bundled data. A DLL that cannot be found yields 0 (caller
// cleanup), the behavior before.

// importPurge returns the bytes the imported function pops on return.
func importPurge(binPath string, ref importRef) int {
	return dllPurge(filepath.Dir(binPath), ref.dll, ref.name, ref.ordinal, 0)
}

var purgeCache sync.Map // "dir|dll|name|ordinal" -> int

func dllPurge(dir, dll, name string, ordinal uint32, depth int) int {
	if depth > 4 || dll == "" {
		return 0
	}
	key := strings.ToLower(dir+"|"+dll+"|"+name) + "|" + strconv.Itoa(int(ordinal))
	if v, ok := purgeCache.Load(key); ok {
		return v.(int)
	}
	n := 0
	// The first candidate that exports the function decides.
	for _, img := range dllCandidates(dir, dll) {
		if got, ok := img.purge(dir, name, ordinal, depth); ok {
			n = got
			break
		}
	}
	purgeCache.Store(key, n)
	return n
}

// dllImage is a 32-bit DLL's code and export/import tables, read once.
type dllImage struct {
	imageBase uint64
	exports   map[string]exportEntry // by name
	byOrdinal map[uint32]exportEntry
	forwards  map[uint32]string // forwarder export RVA -> "DLL.Func"
	imports   map[uint64]importRef
	exec      []cgSection
}

var dllImages sync.Map // resolved path -> *dllImage (nil when unusable)

// dllCandidates lists the 32-bit DLLs that may hold dll's exports, the way
// the loader would see them from the analyzed binary: beside the binary,
// then the 32-bit system directory. An API set name (api-ms-win-*) maps to
// the DLL implementing most of the set (kernelbase, ucrtbase for the CRT);
// its downlevel stub comes last, since those stubs forward back to the
// pre-Windows 8 DLLs (kernel32), which forward to the set again.
func dllCandidates(dir, dll string) []*dllImage {
	lower := strings.ToLower(dll)
	if !strings.HasSuffix(lower, ".dll") {
		lower += ".dll"
	}
	var candidates []string
	if dir != "" {
		candidates = append(candidates, filepath.Join(dir, lower))
	}
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		sys32 := filepath.Join(root, "SysWOW64") // 32-bit DLLs on 64-bit Windows
		if _, err := os.Stat(sys32); err != nil {
			sys32 = filepath.Join(root, "System32")
		}
		candidates = append(candidates, filepath.Join(sys32, lower))
		if strings.HasPrefix(lower, "api-ms-win-") || strings.HasPrefix(lower, "ext-ms-win-") {
			impl := "kernelbase.dll"
			if strings.HasPrefix(lower, "api-ms-win-crt-") {
				impl = "ucrtbase.dll"
			}
			candidates = append(candidates, filepath.Join(sys32, impl), filepath.Join(sys32, "downlevel", lower))
		}
	}
	var out []*dllImage
	for _, c := range candidates {
		v, ok := dllImages.Load(c)
		if !ok {
			v = readDLL32(c)
			dllImages.Store(c, v)
		}
		if img := v.(*dllImage); img != nil {
			out = append(out, img)
		}
	}
	return out
}

func readDLL32(path string) *dllImage {
	f, err := pe.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if f.FileHeader.Machine != 0x14c {
		return nil // a 64-bit DLL of the same name: not this image's
	}
	img := &dllImage{imageBase: peImageBase(f), exports: map[string]exportEntry{},
		byOrdinal: map[uint32]exportEntry{}, forwards: map[uint32]string{}}
	for _, e := range parseExports(f) {
		if e.name != "" {
			img.exports[e.name] = e
		}
		img.byOrdinal[e.ordinal] = e
		if e.forwarder {
			img.forwards[e.rva] = readPEString(f, e.rva)
		}
	}
	img.imports = peImports(f, img.imageBase)
	for _, s := range f.Sections {
		if s.Characteristics&0x20000000 != 0 {
			if d, err := s.Data(); err == nil {
				img.exec = append(img.exec, cgSection{rva: s.VirtualAddress, data: d})
			}
		}
	}
	return img
}

// purge resolves name/ordinal in this DLL and walks its code to ret N;
// ok is false when the DLL does not export it.
func (img *dllImage) purge(dir, name string, ordinal uint32, depth int) (int, bool) {
	e, ok := img.exports[name]
	if name == "" || !ok {
		if e, ok = img.byOrdinal[ordinal]; !ok || name != "" {
			return 0, false
		}
	}
	if e.forwarder {
		// "KERNELBASE.CreateFileA" or "NTDLL.#123"
		fw := img.forwards[e.rva]
		i := strings.LastIndexByte(fw, '.')
		if i <= 0 {
			return 0, true
		}
		target, fn := fw[:i], fw[i+1:]
		if strings.HasPrefix(fn, "#") {
			ord, _ := strconv.Atoi(fn[1:])
			return dllPurge(dir, target, "", uint32(ord), depth+1), true
		}
		return dllPurge(dir, target, fn, 0, depth+1), true
	}
	sec := sectionContainingRVA(img.exec, e.rva)
	if sec == nil {
		return 0, true
	}
	seen := map[int]bool{}
	stack := []int{int(e.rva - sec.rva)}
	for len(stack) > 0 && len(seen) < 4000 {
		pos := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if pos < 0 || pos >= len(sec.data) || seen[pos] {
			continue
		}
		seen[pos] = true
		in, err := x86asm.Decode(sec.data[pos:], 32)
		if err != nil || in.Len == 0 || sec.data[pos] == 0xCC {
			continue
		}
		if in.Op == x86asm.RET {
			if imm, ok := in.Args[0].(x86asm.Imm); ok {
				return int(imm), true
			}
			return 0, true
		}
		// An export that is a jmp through its own import table (a thunk
		// into another DLL) takes that function's size.
		if in.Op == x86asm.JMP {
			if m, ok := in.Args[0].(x86asm.Mem); ok && m.Base == 0 && m.Index == 0 {
				if ref, ok := img.imports[uint64(uint32(m.Disp))]; ok {
					return dllPurge(dir, ref.dll, ref.name, ref.ordinal, depth+1), true
				}
			}
		}
		stack = append(stack, flowSuccessors(sec.data, in, pos)...)
	}
	return 0, true
}
