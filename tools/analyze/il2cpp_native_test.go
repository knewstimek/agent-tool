package analyze

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestIL2CPPNativeHeaderRejectsInvalidInput(t *testing.T) {
	for _, data := range [][]byte{nil, make([]byte, 379), make([]byte, 380)} {
		if _, err := parseIL2CPPNativeMetadata(data); err == nil {
			t.Fatal("invalid header accepted")
		}
	}
	d := make([]byte, 380)
	binary.LittleEndian.PutUint32(d, 0xfab11baf)
	binary.LittleEndian.PutUint32(d[4:], 39)
	binary.LittleEndian.PutUint32(d[8:], 0xffffffff)
	if _, err := parseIL2CPPNativeMetadata(d); err == nil {
		t.Fatal("out-of-file section accepted")
	}
}

// Optional independent exporter comparison. Paths and corpus-derived names are
// supplied only through the environment and never become public test fixtures.
func TestIL2CPPNativeMetadataCorpus(t *testing.T) {
	metadataPath, binaryPath, reference := os.Getenv("AGENT_TOOL_TEST_IL2CPP_METADATA"), os.Getenv("AGENT_TOOL_TEST_IL2CPP_BINARY"), os.Getenv("AGENT_TOOL_TEST_IL2CPP_REFERENCE")
	if metadataPath == "" || binaryPath == "" || reference == "" {
		t.Skip("optional local corpus")
	}
	d, err := readIL2CPPBounded(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseIL2CPPNativeMetadata(d)
	if err != nil {
		t.Fatal(err)
	}
	im, err := openIL2CPPNativeImage(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	r, err := im.registrationV39(uint64(m.tables[19].count))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.decode(int(r.typesCount)); err != nil {
		t.Fatal(err)
	}
	addresses, err := im.methodAddresses(m, r)
	if err != nil {
		t.Fatal(err)
	}
	nativeTypes := &il2cppNativeTypes{image: im, metadata: m, registration: r, tokens: map[int]string{}, names: map[int]string{}}
	records := nativeTypes.methodRecords(addresses)
	f, err := os.Open(reference)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ref il2cppClassExport
	if err := json.NewDecoder(f).Decode(&ref); err != nil {
		t.Fatal(err)
	}
	if len(m.methods) != len(ref.Methods) {
		t.Fatalf("method count differs: native=%d reference=%d", len(m.methods), len(ref.Methods))
	}
	issues := 0
	var samples []string
	for _, method := range ref.Methods {
		i, err := strconv.Atoi(method.ID)
		if err != nil || i < 0 || i >= len(m.methods) {
			t.Fatal("invalid reference method ID")
		}
		got := m.methods[i]
		if strconv.Itoa(got.owner) != method.Owner || got.parameterCount != len(method.Params) || (got.flags&0x10 != 0) != method.Static {
			t.Fatalf("method definition %d differs from independent exporter", i)
		}
		want := map[uint64]bool{}
		for _, s := range method.Addresses {
			v, e := strconv.ParseUint(s[2:], 16, 64)
			if e != nil {
				t.Fatal(e)
			}
			want[v] = true
		}
		if len(want) != len(addresses[i]) {
			t.Fatalf("method %d address count differs: got=%d reference=%d", i, len(addresses[i]), len(want))
		}
		for _, v := range addresses[i] {
			if !want[v] {
				t.Fatalf("method %d address mismatch", i)
			}
		}
		gp := il2cppTSVPrototype(records[i].Static, records[i].Ret, strings.Join(records[i].Params, ","), nil)
		referenceRet := method.Ret
		if rt, ok := nativeTypes.runtime(m.methods[i].ret); ok && rt.bits&(1<<29) != 0 {
			// Legacy reference export loses primitive byref returns. Native
			// metadata and pointer-returning code require pointer storage.
			referenceRet = "ptr:byref"
		}
		referenceParams := append([]string(nil), method.Params...)
		for j, token := range referenceParams {
			rt, _ := nativeTypes.runtime(m.params[got.parameterStart+j])
			// ParameterAttributes.Out alone does not change native storage.
			// The reference exporter conflates [Out] scalar and byref parameters.
			if rt.bits&2 != 0 && rt.bits&(1<<29) == 0 && strings.HasPrefix(token, "ptr:") {
				switch byte(rt.bits >> 16) {
				case 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0x18, 0x19:
					referenceParams[j] = records[i].Params[j]
				}
			}
		}
		wp := il2cppTSVPrototype(method.Static, referenceRet, strings.Join(referenceParams, ","), nil)
		// Closed generic value layouts are deliberately unsupported rather than
		// trusting the legacy exporter's unconditional pointer approximation.
		unsupported := strings.HasPrefix(records[i].Ret, "unknown:generic-value")
		for _, token := range records[i].Params {
			unsupported = unsupported || token == "unknown:generic-value"
		}
		if unsupported && gp == nil {
			continue
		}
		if (gp == nil) != (wp == nil) || gp != nil && gp.abi != wp.abi {
			issues++
			if len(samples) < 8 {
				samples = append(samples, fmt.Sprintf("method %d: native=%s(%v), reference=%s(%v)", i, records[i].Ret, records[i].Params, method.Ret, method.Params))
			}
		}
	}
	if off := im.vtableOffset(); off != ref.VTableOffset {
		t.Fatalf("runtime vtable offset: native=%#x reference=%#x", off, ref.VTableOffset)
	}
	classes, err := nativeTypes.classRecords()
	if err != nil {
		t.Fatal(err)
	}
	refClasses := map[string]il2cppClassRecord{}
	for _, c := range ref.Classes {
		refClasses[c.ID] = c
	}
	for _, c := range classes {
		want, ok := refClasses[c.ID]
		if !ok {
			continue
		}
		if c.Name != want.Name || c.Size != want.Size || len(c.Slots) != len(want.Slots) {
			t.Fatalf("class %s layout differs", c.ID)
		}
		for j, s := range c.Slots {
			if s != want.Slots[j] {
				t.Fatalf("class %s slot %d differs", c.ID, s.Index)
			}
		}
	}
	idx := &il2cppPrototypes{binarySHA256: ref.BinaryHash, methods: map[uint64]*il2cppPrototype{}}
	for i, row := range records {
		p := il2cppTSVPrototype(row.Static, row.Ret, strings.Join(row.Params, ","), nil)
		for _, va := range addresses[i] {
			idx.add(va, p)
		}
	}
	idx.finish()
	export := il2cppClassExport{Version: 1, BinaryHash: ref.BinaryHash, PointerSize: 8, VTableOffset: im.vtableOffset(), Classes: classes, Methods: records}
	if _, err := indexIL2CPPClasses(&export, idx); err != nil {
		t.Fatal(err)
	}
	if issues != 0 {
		t.Fatalf("ABI differences=%d; bounded examples=%v", issues, samples)
	}
	t.Logf("types=%d methods=%d fields=%d params=%d images=%d: all method owners/arity/static match", len(m.types), len(m.methods), len(m.fields), len(m.params), len(m.images))
}
