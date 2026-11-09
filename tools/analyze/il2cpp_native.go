package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Only inspect adjacent standard Unity data directories. Never recursively
// crawl a workspace or silently select one of multiple metadata files.
func discoverIL2CPPMetadata(binary string) ([]string, error) {
	root := filepath.Dir(binary)
	candidates := []string{filepath.Join(root, "global-metadata.dat"), filepath.Join(root, "Metadata", "global-metadata.dat"), filepath.Join(root, "il2cpp_data", "Metadata", "global-metadata.dat")}
	f, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(257)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 256 {
		return nil, fmt.Errorf("metadata discovery directory exceeds 256 entries; specify il2cpp_signatures explicitly")
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), "_data") {
			candidates = append(candidates, filepath.Join(root, e.Name(), "il2cpp_data", "Metadata", "global-metadata.dat"))
		}
	}
	var found []string
	for _, p := range candidates {
		s, err := os.Stat(p)
		if err == nil && s.Mode().IsRegular() {
			found = append(found, p)
		} else if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	return found, nil
}

func nativeIL2CPPPrototypes(binary, metadata string) (*il2cppPrototypes, error) {
	data, err := readIL2CPPBounded(metadata)
	if err != nil {
		return nil, err
	}
	m, err := parseIL2CPPNativeMetadata(data)
	if err != nil {
		return nil, err
	}
	im, err := openIL2CPPNativeImage(binary)
	if err != nil {
		return nil, err
	}
	r, err := im.registrationV39(uint64(m.tables[19].count))
	if err != nil {
		return nil, err
	}
	if err = m.decode(int(r.typesCount)); err != nil {
		return nil, err
	}
	addresses, err := im.methodAddresses(m, r)
	if err != nil {
		return nil, err
	}
	types := &il2cppNativeTypes{image: im, metadata: m, registration: r, tokens: map[int]string{}, names: map[int]string{}}
	records := types.methodRecords(addresses)
	idx := &il2cppPrototypes{path: metadata, methods: map[uint64]*il2cppPrototype{}}
	for i, record := range records {
		proto := il2cppTSVPrototype(record.Static, record.Ret, strings.Join(record.Params, ","), nil)
		for _, va := range addresses[i] {
			idx.add(va, proto)
		}
	}
	idx.finish()
	// Optional class decoration requires a proven runtime layout. Missing/changed
	// accessor code leaves direct signatures usable without inventing slot offsets.
	if offset := im.vtableOffset(); offset != 0 {
		classes, err := types.classRecords()
		if err != nil {
			return nil, err
		}
		f, err := os.Open(binary)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		idx.binarySHA256 = hex.EncodeToString(h.Sum(nil))
		export := il2cppClassExport{Version: 1, BinaryHash: idx.binarySHA256, PointerSize: 8, VTableOffset: offset, Classes: classes, Methods: records}
		idx.classes, err = indexIL2CPPClasses(&export, idx)
		if err != nil {
			return nil, err
		}
		mh := sha256.Sum256(data)
		idx.classes.prefix = "il2cpp:native-v39:" + idx.binarySHA256 + ":" + hex.EncodeToString(mh[:]) + ":"
	}
	return idx, nil
}
