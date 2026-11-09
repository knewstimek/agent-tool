package analyze

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestIL2CPPNativeRuntimeStorage(t *testing.T) {
	nt := &il2cppNativeTypes{}
	for _, tc := range []struct {
		bits uint32
		want string
	}{
		{0x00090000, "uint32"}, {0x20090000, "ptr:byref"},
		{0x80180002, "int64"}, {0x20180002, "ptr:byref"},
		{0x000c0000, "float32"}, {0x00130000, "unknown:generic-parameter"},
	} {
		if got := nt.typeToken(il2cppRuntimeType{bits: tc.bits}, 0); got != tc.want {
			t.Fatalf("bits %#x: got %s want %s", tc.bits, got, tc.want)
		}
	}
}

func TestIL2CPPNativeVTableAccessor(t *testing.T) {
	// movzx eax,word ptr [rdx+0x50]; mov rcx,[rcx]; add rax,0x14;
	// add rax,rax; mov rax,[rcx+rax*8]; ret. No binary-specific offsets.
	body := []byte{0x0f, 0xb7, 0x42, 0x50, 0x48, 0x8b, 0x09, 0x48, 0x83, 0xc0, 0x14, 0x48, 0x01, 0xc0, 0x48, 0x8b, 0x04, 0xc1, 0xc3}
	for _, tc := range []struct {
		name   string
		prefix []byte
		want   int32
	}{
		{"plain", nil, 0x138}, {"conditional", []byte{0x75, 0x7f}, 0x138},
		{"call", []byte{0xe8, 0, 0, 0, 0}, 0}, {"return", []byte{0xc3}, 0},
		{"clobber", []byte{0x48, 0x31, 0xd2}, 0},
		{"partial_clobber", []byte{0xb2, 0}, 0},
		{"pointer_truncation", []byte{0x89, 0xd2}, 0},
		{"thunk", []byte{0xeb, 0}, 0x138},
	} {
		t.Run(tc.name, func(t *testing.T) {
			im := &il2cppNativeImage{exports: map[string]uint64{"il2cpp_object_get_virtual_method": 0x1000}, sections: []il2cppNativeSection{{va: 0x1000, data: append(append([]byte{}, tc.prefix...), body...), exec: true}}}
			if got := im.vtableOffset(); got != tc.want {
				t.Fatalf("got %#x want %#x", got, tc.want)
			}
		})
	}
	// A jump cycle must terminate within the bounded inspection budget.
	im := &il2cppNativeImage{exports: map[string]uint64{"il2cpp_object_get_virtual_method": 0x1000}, sections: []il2cppNativeSection{{va: 0x1000, data: []byte{0xeb, 0xfe}, exec: true}}}
	if im.vtableOffset() != 0 {
		t.Fatal("jump cycle accepted")
	}
}

func TestIL2CPPNativeOwnership(t *testing.T) {
	for _, tc := range []string{"valid", "overlap", "unmapped_type", "wrong_owner", "reused_method", "unmapped_method", "native_type"} {
		t.Run(tc, func(t *testing.T) {
			m := &il2cppNativeMetadata{
				types:   []il2cppNativeTypeDef{{byval: 0, methodStart: 0, methodCount: 1}, {byval: 1, methodStart: 1, methodCount: 1}},
				methods: []il2cppNativeMethod{{owner: 0}, {owner: 1}}, images: []il2cppNativeAssembly{{start: 0, count: 2}},
			}
			switch tc {
			case "overlap":
				m.images = append(m.images, il2cppNativeAssembly{start: 1, count: 1})
			case "unmapped_type":
				m.images[0].count = 1
			case "wrong_owner":
				m.methods[1].owner = 0
			case "reused_method":
				m.types[1].methodStart = 0
			case "unmapped_method":
				m.types[1].methodCount = 0
			case "native_type":
				m.types[0].byval = 2
			}
			err := m.validateOwnership(2)
			if (err == nil) != (tc == "valid") {
				t.Fatalf("unexpected ownership validation: %v", err)
			}
		})
	}
}

func TestIL2CPPNativeDiscoveryAndIdentity(t *testing.T) {
	root := t.TempDir()
	image := filepath.Join(root, "image.dll")
	metadata := filepath.Join(root, "Application_Data", "il2cpp_data", "Metadata", "global-metadata.dat")
	if err := os.MkdirAll(filepath.Dir(metadata), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadata, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := il2cppScriptPath(image, ""); got != metadata {
		t.Fatalf("metadata not discovered: %s", got)
	}
	if idx, err := loadIL2CPPPrototypes(image, "", &cgBinary{}); idx != nil || err != nil {
		t.Fatal("unrelated PE loaded nearby Unity metadata")
	}
	if _, err := loadIL2CPPPrototypes(image, metadata, &cgBinary{}); err == nil {
		t.Fatal("explicit metadata selection was ignored")
	}
	if idx, err := loadIL2CPPPrototypes(image, "", &cgBinary{symbols: map[uint64]string{0x1000: "il2cpp_init"}}); err != nil || idx == nil || idx.note == "" || idx.prototype(0x1000) != nil {
		t.Fatal("automatic extraction failure did not preserve inference with a note")
	}
	before := workerKey(decompileRequest{Path: image})
	if err := os.WriteFile(metadata, []byte("changed metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	if workerKey(decompileRequest{Path: image}) == before {
		t.Fatal("metadata change reused stale worker")
	}
	if idx, err := loadIL2CPPPrototypes(image, "none", nil); idx != nil || err != nil {
		t.Fatal("none did not disable native loading")
	}
	if err := os.WriteFile(filepath.Join(root, "global-metadata.dat"), []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIL2CPPPrototypes(image, "", nil); err == nil {
		t.Fatal("ambiguous discovery selected a metadata file")
	}
	script := filepath.Join(root, "methodsigs.tsv")
	if err := os.WriteFile(script, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if got := il2cppScriptPath(image, ""); got != script {
		t.Fatal("explicit sidecar discovery lost priority")
	}
}

func TestIL2CPPNativeBoundedReads(t *testing.T) {
	im := &il2cppNativeImage{sections: []il2cppNativeSection{{va: 0x1000, data: make([]byte, 16)}}}
	if im.read(^uint64(0)-1, 8) != nil || im.read(0x1008, ^uint64(0)) != nil || im.read(0x100f, 2) != nil {
		t.Fatal("out of range read accepted")
	}
	binary.LittleEndian.PutUint64(im.sections[0].data, 0x1234)
	if p, ok := im.pointer(0x1000); !ok || p != 0x1234 {
		t.Fatal("mapped pointer lost")
	}
	for _, n := range []int{1, 255, 256, 65535, 65536} {
		width := il2cppIndexWidth(n)
		c := il2cppNativeCursor{data: []byte{255, 255, 255, 255}}
		if c.index(width) != -1 {
			t.Fatal("compressed null sentinel lost")
		}
	}
}
