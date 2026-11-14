package analyze

import (
	"debug/pe"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// An import by ordinal has its name only in the exporting DLL, so the DLL the
// loader would use is read. Without it the import stays Ordinal_<n>.

// systemDLLDir is the Windows directory holding system DLLs of the given PE
// machine type, "" on other hosts.
func systemDLLDir(machine uint16) string {
	if runtime.GOOS != "windows" {
		return ""
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	if machine == 0x14c {
		// 32-bit DLLs live in SysWOW64 on 64-bit Windows.
		if dir := filepath.Join(root, "SysWOW64"); dirExists(dir) {
			return dir
		}
	}
	return filepath.Join(root, "System32")
}

func dirExists(dir string) bool {
	st, err := os.Stat(dir)
	return err == nil && st.IsDir()
}

// dllSearchPaths lists where the loader would find dll from a binary in dir:
// beside the binary, then the system directory of its machine type.
func dllSearchPaths(dir, dll string, machine uint16) []string {
	name := strings.ToLower(dll)
	// The name comes from the analyzed (untrusted) binary: a path in it must
	// not steer the lookup outside the two directories.
	if strings.ContainsAny(name, `/\:`) {
		return nil
	}
	if filepath.Ext(name) == "" {
		name += ".dll"
	}
	var paths []string
	if dir != "" {
		paths = append(paths, filepath.Join(dir, name))
	}
	if sys := systemDLLDir(machine); sys != "" {
		paths = append(paths, filepath.Join(sys, name))
	}
	return paths
}

var dllOrdinalNames sync.Map // path -> map[uint32]string (nil: no usable DLL there)

// importOrdinalName returns the name dll exports for ordinal, "" when the DLL
// is not on this host or exports that ordinal without a name. The first DLL of
// the binary's machine type on the search path decides, as for the loader.
func importOrdinalName(binPath string, machine uint16, dll string, ordinal uint32) string {
	if binPath == "" || dll == "" {
		return ""
	}
	for _, path := range dllSearchPaths(filepath.Dir(binPath), dll, machine) {
		v, ok := dllOrdinalNames.Load(path)
		if !ok {
			v, _ = dllOrdinalNames.LoadOrStore(path, readOrdinalNames(path, machine))
		}
		if names := v.(map[uint32]string); names != nil {
			return names[ordinal]
		}
	}
	return ""
}

func readOrdinalNames(path string, machine uint16) map[uint32]string {
	f, err := pe.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if f.FileHeader.Machine != machine {
		return nil // a DLL of the same name for another architecture
	}
	names := map[uint32]string{}
	for _, e := range parseExports(f) {
		if e.name != "" {
			names[e.ordinal] = e.name
		}
	}
	return names
}
