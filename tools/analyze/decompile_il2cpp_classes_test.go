package analyze

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knewstimek/gosleigh/pkg/analysis"
	"github.com/knewstimek/gosleigh/pkg/decomp"
	"github.com/knewstimek/gosleigh/pkg/pcode"
	"github.com/knewstimek/gosleigh/pkg/specs"
)

func il2cppClassFixture(t *testing.T) (*il2cppPrototypes, il2cppClassExport) {
	t.Helper()
	idx, err := parseIL2CPPMethodsTSV(strings.NewReader("# binary_sha256="+strings.Repeat("a", 64)+"\n0x1000\t0\tbool\t\tignored\n"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return idx, il2cppClassExport{
		Version: 1, BinaryHash: strings.Repeat("a", 64), PointerSize: 8, VTableOffset: 16,
		Classes: []il2cppClassRecord{{ID: "1", Name: "Example", Size: 16, Slots: []il2cppVirtualSlot{{Index: 0, Method: "slot"}}}},
		Methods: []il2cppMethodRecord{
			{ID: "caller", Owner: "1", Addresses: []string{"0x1000"}, Ret: "bool"},
			{ID: "slot", Owner: "1", Ret: "bool", Params: []string{"int32"}},
		},
	}
}

func TestIL2CPPVirtualCallPrototype(t *testing.T) {
	idx, export := il2cppClassFixture(t)
	var err error
	idx.classes, err = indexIL2CPPClasses(&export, idx)
	if err != nil {
		t.Fatal(err)
	}
	idx.classes.prefix = t.Name() + ":"
	spec, err := specs.X86(64, specs.CompilerWindows)
	if err != nil {
		t.Fatal(err)
	}
	// this->klass->slot(this, 7, methodInfo), with scratch r9=5.
	code := []byte{0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x01, 0x4c, 0x8b, 0x40, 0x18, 0xba, 7, 0, 0, 0, 0x41, 0xb9, 5, 0, 0, 0, 0xff, 0x50, 0x10, 0x48, 0x83, 0xc4, 0x28, 0xc3}
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: 0x1000, Data: code, Exec: true}})
	if err != nil {
		t.Fatal(err)
	}
	h := &decompHost{funcs: map[uint64]string{0x1000: "caller"}, il2cpp: idx}
	fn := decomp.Function{Entry: 0x1000, Name: "caller", Host: h}
	analysis.NewEnhanced(prog).Apply(&fn)
	result, err := prog.Decompile(fn)
	if err != nil {
		t.Fatal(err)
	}
	got := result.C
	if !strings.Contains(got, "slot_0_methodPtr") || !strings.Contains(got, "slot_0_method)") || strings.Contains(got, ",5)") || strings.Contains(got, ", 5)") {
		t.Fatalf("typed virtual call did not retain exactly this, int, MethodInfo:\n%s", got)
	}
	// Returned slices belong to the caller, including the cached decoration.
	p := idx.prototype(0x1000)
	p.Params[0].Name = "modified"
	if idx.prototype(0x1000).Params[0].Name == "modified" {
		t.Fatal("cached prototype is mutable through a returned slice")
	}
}

func TestIL2CPPClassSourceValidation(t *testing.T) {
	for _, test := range []string{"hash", "pointer", "offset", "duplicateClass", "duplicateSlot", "missingMethod", "duplicateMethod", "contradictingABI"} {
		t.Run(test, func(t *testing.T) {
			idx, export := il2cppClassFixture(t)
			switch test {
			case "hash":
				export.BinaryHash = strings.Repeat("b", 64)
			case "pointer":
				export.PointerSize = 4
			case "offset":
				export.VTableOffset = 17
			case "duplicateClass":
				export.Classes = append(export.Classes, export.Classes[0])
			case "duplicateSlot":
				export.Classes[0].Slots = append(export.Classes[0].Slots, export.Classes[0].Slots[0])
			case "missingMethod":
				export.Classes[0].Slots[0].Method = "absent"
			case "duplicateMethod":
				export.Methods = append(export.Methods, export.Methods[0])
			case "contradictingABI":
				export.Methods[0].Ret = "float32"
			}
			if _, err := indexIL2CPPClasses(&export, idx); err == nil {
				t.Fatal("invalid export was accepted")
			}
		})
	}
}

func TestIL2CPPClassOverlapsAndCodeTypeIdentity(t *testing.T) {
	idx, export := il2cppClassFixture(t)
	export.Classes[0].Size = 32
	export.Classes[0].Fields = []il2cppClassField{
		{Name: "first", Offset: 16, Type: "ref:Example"},
		{Name: "overlap", Offset: 16, Type: "int32"},
		{Name: "outside", Offset: 31, Type: "int32"},
		{Name: "safe", Offset: 24, Type: "uint32"},
	}
	c, err := indexIL2CPPClasses(&export, idx)
	if err != nil {
		t.Fatal(err)
	}
	build := func(prefix string) *pcode.HostTypeDesc {
		b := il2cppClassBuilder{source: c, prefix: prefix, objects: map[string]*pcode.HostTypeDesc{}}
		return b.object("1", 0)
	}
	one, two := build("one"), build("two")
	if len(one.Fields) != 2 || one.Fields[1].Offset != 24 {
		t.Fatal("overlapping or out-of-bounds object fields remained typed")
	}
	fn := one.Fields[0].Type.Elem.Fields[0].Type.Elem
	other := two.Fields[0].Type.Elem.Fields[0].Type.Elem
	if fn.Name == "" || fn.Name == other.Name || fn.Proto == nil || len(fn.Proto.Params) != 3 {
		t.Fatal("function code type has no unique name or lacks implicit ABI parameters")
	}
}

func TestIL2CPPClassAmbiguityAndAggregateReturn(t *testing.T) {
	idx, export := il2cppClassFixture(t)
	alias := export.Methods[0]
	alias.ID, alias.Owner = "shared", "other"
	export.Methods = append(export.Methods, alias)
	export.Methods[1].Ret = "val:12:Vector"
	c, err := indexIL2CPPClasses(&export, idx)
	if err != nil {
		t.Fatal(err)
	}
	if c.byVA[0x1000] != nil {
		t.Fatal("shared address with different receiver types was decorated")
	}
	b := il2cppClassBuilder{source: c, prefix: t.Name(), objects: map[string]*pcode.HostTypeDesc{}}
	obj := b.object("1", 0)
	if len(obj.Fields[0].Type.Elem.Fields) != 0 {
		t.Fatal("hidden-buffer return was incorrectly locked as a virtual prototype")
	}
}

func TestIL2CPPClassSidecarIdentity(t *testing.T) {
	idx, export := il2cppClassFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "methodsigs.tsv")
	before := il2cppSourceIdentity("unused", path)
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "il2cpp-types.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if before == il2cppSourceIdentity("unused", path) {
		t.Fatal("adding class metadata did not invalidate the worker")
	}
	if err := loadIL2CPPClasses(path, idx); err != nil {
		t.Fatal(err)
	}
	if idx.classes == nil || idx.classes.prefix == "" || idx.prototype(0x1000) == nil {
		t.Fatal("binary-bound class metadata did not load")
	}
	// Missing false is different from an explicitly declared instance method.
	bad := strings.Replace(string(data), `"static":false,`, "", 1)
	if err := os.WriteFile(filepath.Join(dir, "il2cpp-types.json"), []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadIL2CPPClasses(path, idx); err == nil {
		t.Fatal("missing static flag silently selected the instance calling convention")
	}
}
