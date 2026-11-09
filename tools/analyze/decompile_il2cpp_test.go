package analyze

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agent-tool/common"

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/analysis"
	"github.com/knewstimek/gosleigh/pkg/decomp"
	"github.com/knewstimek/gosleigh/pkg/pcode"
	"github.com/knewstimek/gosleigh/pkg/specs"
)

func TestIL2CPPPrimitiveStorageAndMethodInfo(t *testing.T) {
	for _, c := range []struct {
		name string
		size int32
		meta int
	}{
		{"bool", 1, int(pcode.TYPE_BOOL)}, {"uint8_t", 1, int(pcode.TYPE_UINT)},
		{"uint16_t", 2, int(pcode.TYPE_UINT)}, {"int32_t", 4, int(pcode.TYPE_INT)},
		{"uint32_t", 4, int(pcode.TYPE_UINT)}, {"int64_t", 8, int(pcode.TYPE_INT)},
		{"float", 4, int(pcode.TYPE_FLOAT)}, {"double", 8, int(pcode.TYPE_FLOAT)},
		{"Widget_o*", 8, int(pcode.TYPE_PTR)}, {"Widget_array*", 8, int(pcode.TYPE_PTR)},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := parseIL2CPPPrototype(c.name+" get(Widget_o* __this, "+c.name+" value, const MethodInfo* method);", newIL2CPPTypes(""))
			if p == nil || !p.function.InputLocked || !p.function.OutputLocked || len(p.function.Params) != 3 {
				t.Fatal("prototype was not locked")
			}
			f := p.function
			if f.Output.Size != c.size || int(f.Output.Type.Metatype()) != c.meta || f.Params[1].Size != c.size || int(f.Params[1].Type.Metatype()) != c.meta {
				t.Fatal("incorrect scalar ABI")
			}
			if !f.Params[0].ThisPtr || f.Params[2].Name != "method" || f.Params[2].Size != 8 {
				t.Fatal("this or trailing MethodInfo was lost")
			}
			for _, a := range f.Params {
				if a.Space != "" || a.Offset != 0 {
					t.Fatal("host assigned register storage")
				}
			}
		})
	}
	p := parseIL2CPPPrototype("void empty(void);", newIL2CPPTypes(""))
	if p == nil || !p.function.OutputLocked || p.function.Output.Type.Metatype() != pcode.TYPE_VOID || len(p.function.Params) != 0 {
		t.Fatal("void prototype was not explicitly locked")
	}
}

func TestIL2CPPValueLayoutsAndUnknownTypes(t *testing.T) {
	header := "struct One_o { uint8_t v; }; struct Two_o { uint16_t v; }; struct Four_o { float v; }; struct Eight_o { uint32_t a; uint8_t b; }; struct Large_Fields { float x; float y; float z; }; struct Large_o { Large_Fields fields; };"
	types := newIL2CPPTypes(header)
	for _, c := range []struct {
		name string
		size int32
	}{{"One_o", 1}, {"Two_o", 2}, {"Four_o", 4}, {"Eight_o", 8}, {"Large_o", 12}} {
		p := parseIL2CPPPrototype(c.name+" get("+c.name+" value, const MethodInfo* method);", types)
		if p == nil || !p.function.InputLocked {
			t.Fatalf("layout missing for %s", c.name)
		}
		if c.size <= 8 {
			if !p.function.OutputLocked || p.function.Output.Size != c.size || p.function.Params[0].Size != c.size || p.function.Params[0].Type.Metatype() != pcode.TYPE_UINT {
				t.Fatalf("small aggregate storage: %s", c.name)
			}
		} else if p.function.OutputLocked || p.function.Output != nil || p.function.Params[0].Type.Metatype() != pcode.TYPE_PTR {
			t.Fatal("hidden aggregate return was incorrectly fixed")
		}
	}
	for _, sig := range []string{
		"Unknown_o f(int32_t n);", "void f(Unknown_o n);", "void f(void n);", "void f(int x, ...);",
		"void f(void (*callback)(int));", "bool f(int32_t __this);", "void f(int values[4]);",
	} {
		if parseIL2CPPPrototype(sig, types) != nil {
			t.Errorf("unsupported signature was locked: %s", sig)
		}
	}
	packed := newIL2CPPTypes("#pragma pack(push, 1)\nstruct Packed_o { uint8_t a; uint32_t b; };\n#pragma pack(pop)")
	if parseIL2CPPPrototype("void f(Packed_o value);", packed) != nil {
		t.Fatal("unknown packing was guessed")
	}
	aligned := newIL2CPPTypes("__declspec(align(16)) struct Aligned_o { uint8_t value; };")
	if parseIL2CPPPrototype("void f(Aligned_o value);", aligned) != nil {
		t.Fatal("unknown explicit alignment was guessed")
	}
}

func TestIL2CPPSharedGenericConsensusAndExactAddresses(t *testing.T) {
	data := `{"ScriptString":[{"Value":"ignored"}],"ScriptMethod":[
{"Address":4096,"Signature":"bool f(void* __this, const MethodInfo* method);"},
{"Address":"0x1000","Signature":"bool another(Other_o* __this, const MethodInfo* info);"},
{"Address":8192,"Signature":"bool f(int32_t a);"},
{"Address":8192,"Signature":"bool f(float a);"},
{"Address":8192,"Signature":"bool f(int32_t a);"},
{"Address":12288,"Signature":"bool f(int32_t a);"},
{"Address":12288,"Signature":"Unknown_o f(int32_t a);"},
{"Address":9007199254740993,"Signature":"void f(void);"}]}`
	idx, err := parseIL2CPPScript(strings.NewReader(data), 0, newIL2CPPTypes(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if idx.prototype(4096) == nil || idx.prototype(8192) != nil || idx.prototype(12288) != nil || idx.prototype(9007199254740993) == nil || idx.prototype(9007199254740992) != nil {
		t.Fatal("generic consensus or integer precision failed")
	}
	p := idx.prototype(4096)
	p.Params[0].Size = 99
	if idx.prototype(4096).Params[0].Size == 99 {
		t.Fatal("prototype callers can mutate the index")
	}
	for _, data := range []string{`{}`, `{"ScriptMethod":null}`, `{"ScriptMethod":[],"ScriptMethod":[]}`, `{"ScriptMethod":[]} {}`, `{"ScriptMethod":[{"Address":1.5}]}`, `{"ScriptMethod":[{"Address":-1}]}`} {
		if _, err := parseIL2CPPScript(strings.NewReader(data), 0, newIL2CPPTypes(""), nil); err == nil {
			t.Errorf("invalid script accepted: %s", data)
		}
	}
}

func TestIL2CPPMethodsTSVAndAggregateConsensus(t *testing.T) {
	data := "VA\tstatic\tret\tparams\tname\n" +
		"0x1000\t0\tbool\tint32,float32,ref:Example\tfirst\n" +
		"0x2000\t1\tval:12:Vector\tval:4:Small\tlarge\n" +
		"0x3000\t1\tvoid\tval:12:Vector\tshared1\n" +
		"0x3000\t1\tvoid\tval:16:Other\tshared2\n" +
		"0x4000\t1\tbool\tval:Known\tsized\n" +
		"0x5000\t1\tbool\tval:Missing\tunknown\n"
	idx, err := parseIL2CPPMethodsTSV(strings.NewReader(data), map[string]int32{"Known": 8}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := idx.prototype(0x1000)
	if p == nil || len(p.Params) != 5 || !p.Params[0].ThisPtr || p.Params[4].Name != "method" || p.Params[2].Type.Metatype() != pcode.TYPE_FLOAT {
		t.Fatal("TSV implicit args or scalar types are incorrect")
	}
	large := idx.prototype(0x2000)
	if large == nil || large.OutputLocked || large.Output != nil || large.Params[0].Size != 4 || idx.prototype(0x3000) != nil || idx.prototype(0x4000) == nil || idx.prototype(0x5000) != nil {
		t.Fatal("TSV value-size or generic conflict handling failed")
	}
}

func TestIL2CPPHostPriorityAndNoRenaming(t *testing.T) {
	idx, err := parseIL2CPPMethodsTSV(strings.NewReader("0x1000\t0\tbool\t\tIgnoredName\n"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &decompHost{funcs: map[uint64]string{0x1000: "OriginalName"}, il2cpp: idx}
	p, ok := h.QueryFunction(address.Address{Offset: 0x1000})
	if !ok || p.Name != "OriginalName" || !p.InputLocked || !p.OutputLocked || p.ExtraPop != 8 {
		t.Fatal("IL2CPP prototype was not applied independently of names")
	}
	fixture := filepath.Join("testdata", "pdb", "fixture_x64.exe")
	target, err := loadDecompileTargetWithIL2CPP(fixture, "", false, filepath.Join(t.TempDir(), "does-not-exist.tsv"))
	if err != nil || target.host.debug == nil || target.host.il2cpp != nil {
		t.Fatalf("PDB did not take precedence: %v", err)
	}
}

func TestIL2CPPWorkerIdentityAndAutoDiscovery(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin", "build", "image.dll")
	script := filepath.Join(filepath.Dir(bin), "methodsigs.tsv")
	if err := os.MkdirAll(filepath.Dir(script), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	req := decompileRequest{Path: bin}
	if il2cppScriptPath(bin, "") != script {
		t.Fatal("TSV auto-discovery failed")
	}
	first := workerKey(req)
	if err := os.WriteFile(script, []byte("second, longer"), 0600); err != nil {
		t.Fatal(err)
	}
	if first == workerKey(req) {
		t.Fatal("changed signature file reused stale worker")
	}
	req.IL2CPPScript = "none"
	if workerKey(req) == first || il2cppScriptPath(bin, "none") != "" {
		t.Fatal("disable option was ignored")
	}
}

func TestIL2CPPRequestAliasPathIsResolvedOnce(t *testing.T) {
	root := t.TempDir()
	oldWorkspace := common.GetWorkspace()
	common.SetWorkspace(root)
	t.Cleanup(func() { common.SetWorkspace(oldWorkspace) })
	ctx := t.Context()
	scope := common.LocalAliasScope(ctx, nil)
	if err := common.UpdateDirectoryAliases(ctx, nil, scope, map[string]string{"sig": root}, nil, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = common.UpdateDirectoryAliases(ctx, nil, scope, nil, []string{"sig"}, false) })
	oldRunner := decompileRunner
	t.Cleanup(func() { decompileRunner = oldRunner })
	var selected string
	decompileRunner = func(_ context.Context, req decompileRequest, _ time.Duration) ([]decompileLine, string) {
		selected = req.IL2CPPScript
		return []decompileLine{{Kind: "load"}, {Kind: "done"}}, ""
	}
	fixture, err := filepath.Abs(filepath.Join("testdata", "pdb", "fixture_x64.exe"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = Handle(ctx, nil, AnalyzeInput{Operation: "decompile", FilePath: fixture, VA: "0x1000", IL2CPPSignatures: "@sig/methodsigs.tsv"})
	if err != nil || selected != filepath.Join(root, "methodsigs.tsv") {
		t.Fatalf("signature option was not resolved correctly: selected=%q err=%v", selected, err)
	}
}

func TestIL2CPPBinaryIdentityAndBOM(t *testing.T) {
	hash := strings.Repeat("0", 64)
	data := "\ufeff# methodsigs-v1\n# binary_sha256=" + hash + "\nVA\tstatic\tret\tparams\tname\n0x1000\t1\tbool\t\tf\n"
	idx, err := parseIL2CPPMethodsTSV(strings.NewReader(data), nil, nil)
	if err != nil || idx.binarySHA256 != hash || idx.prototype(0x1000) == nil {
		t.Fatal("BOM or binary identity header was lost")
	}
	for _, bad := range []string{"# binary_sha256=bad\n", "# binary_sha256=" + hash + "\n# binary_sha256=" + strings.Repeat("1", 64) + "\n"} {
		if _, err := parseIL2CPPMethodsTSV(strings.NewReader(bad), nil, nil); err == nil {
			t.Fatal("invalid hash header accepted")
		}
	}
	script := filepath.Join(t.TempDir(), "methodsigs.tsv")
	if err := os.WriteFile(script, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join("testdata", "pdb", "fixture_x64.exe")
	if _, err := loadDecompileTargetWithIL2CPP(fixture, "none", false, script); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("mismatched signature source was not rejected: %v", err)
	}
}

func TestIL2CPPLockedCalleesRecoverBoolWrapper(t *testing.T) {
	spec, err := specs.X86(64, specs.CompilerWindows)
	if err != nil {
		t.Fatal(err)
	}
	code := make([]byte, 0x300)
	copy(code, []byte{0x48, 0x83, 0xec, 0x28, 0xe8, 0xf7, 0, 0, 0, 0x84, 0xc0, 0x74, 0x0a, 0xe8, 0xee, 1, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3, 0x31, 0xc0, 0x48, 0x83, 0xc4, 0x28, 0xc3})
	copy(code[0x100:], []byte{0xb0, 1, 0xc3})
	copy(code[0x200:], []byte{0xb0, 1, 0xc3})
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: 0x1000, Data: code, Exec: true}})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := parseIL2CPPMethodsTSV(strings.NewReader("0x1100\t1\tbool\t\tcheck\n0x1200\t1\tbool\t\tresult\n"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &decompHost{funcs: map[uint64]string{0x1000: "wrapper", 0x1100: "check", 0x1200: "result"}, il2cpp: idx}
	fn := decomp.Function{Entry: 0x1000, Name: "wrapper", Host: h}
	analysis.NewEnhanced(prog).Apply(&fn)
	res, err := prog.Decompile(fn)
	if err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprint(res)
	if !strings.Contains(text, "bool wrapper(") || !strings.Contains(text, "result(") || !(strings.Contains(text, "false") || strings.Contains(text, "return 0")) {
		t.Fatalf("bool/zero/callee return paths were not recovered:\n%s", text)
	}
}
