package analyze

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSplitQualified(t *testing.T) {
	for _, c := range []struct{ in, ns, name string }{
		{"main", "", "main"},
		{"Player::TakeDamage", "Player", "TakeDamage"},
		{"A::B<C::D>::f", "A::B<C::D>", "f"},
		{"GlobalVectorConstants::`dynamic initializer for 'A::B''", "GlobalVectorConstants", "`dynamic initializer for 'A::B''"},
		{"std::vector<int>::operator()", "std::vector<int>", "operator()"},
		{"f(A::B)", "", "f(A::B)"},
	} {
		ns, name := splitQualified(c.in)
		if ns != c.ns || name != c.name {
			t.Errorf("splitQualified(%q) = %q, %q; want %q, %q", c.in, ns, name, c.ns, c.name)
		}
	}
	if ns, name := displayParts("geo::Rect::`vftable'"); ns != "geo::Rect" || name != "vftable" {
		t.Errorf("displayParts(vftable) = %q, %q", ns, name)
	}
	if got := ghidraName("TSharedRef<IMessageToken,0> const &"); got != "TSharedRef<IMessageToken,0>_const_&" {
		t.Errorf("ghidraName = %q", got)
	}
}

// The fixtures (from the gopdb repository, built by MSVC from a known
// source) let the PDB host be checked against what the source declares.
func decompileFixture(t *testing.T, arch, va string) string {
	t.Helper()
	exe := filepath.Join("testdata", "pdb", "fixture_"+arch+".exe")
	out, err := opDecompile(context.Background(), AnalyzeInput{FilePath: exe, VA: va, MaxOutputChars: 200000})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "fixture_"+arch+".pdb (") {
		t.Fatalf("%s: PDB not applied:\n%s", arch, out)
	}
	return out
}

func TestDecompilePDBPrototypes(t *testing.T) {
	for _, arch := range []string{"x86", "x64"} {
		out := decompileFixture(t, arch, "sum_points, scale, use_node, fast_call, geo::Rect::area, fatal")
		for _, want := range []string{
			// Parameter names and types from the PDB, storage from the model.
			"sum_points(Point *pts, int n)",
			"scale(double v, float f, int k)",
			"use_node(Node *n, Color c)",
			// Struct fields reach the body.
			"n->color",
			"Rect::area(Rect *this)",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: output lacks %q:\n%s", arch, want, out)
			}
		}
		// Type definitions are left out of the agent-facing output.
		if strings.Contains(out, "struct Node {") {
			t.Errorf("%s: type definitions not stripped:\n%s", arch, out)
		}
		if arch == "x86" && !strings.Contains(out, "__fastcall fast_call(int a, int b, int c)") {
			t.Errorf("x86: fast_call convention lost:\n%s", out)
		}
	}
}

// Local variables keep their PDB names and types: a structure local is one
// variable whose members are accessed, not a run of loose stack words.
func TestDecompilePDBLocals(t *testing.T) {
	for _, arch := range []string{"x86", "x64"} {
		out := decompileFixture(t, arch, "entry")
		for _, want := range []string{"Rect r;", "Point pts [2];", "g_rect = &r;", "r.w_ = 3;", "r.super_Shape.id_ = 1;"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: output lacks %q:\n%s", arch, want, out)
			}
		}
	}
}

// Bitfield members reach the decompiler as their storage unit plus the
// field's bits in it (struct Flags { ready:1; mode:3; rest:28; }).
func TestPDBBitfieldMembers(t *testing.T) {
	target, err := loadDecompileTarget(filepath.Join("testdata", "pdb", "fixture_x64.exe"), "", false)
	if err != nil {
		t.Fatal(err)
	}
	pi := target.host.debug.(*pdbInfo)
	ti, ok := pi.types.tt.ByName("Flags")
	if !ok {
		t.Fatal("Flags not in the PDB")
	}
	d := pi.types.desc(ti)
	var got []string
	for _, f := range d.Fields {
		got = append(got, fmt.Sprintf("%s@%d:%d+%d", f.Name, f.Offset, f.BitOffset, f.BitSize))
	}
	if want := []string{"ready@0:0+1", "mode@0:1+3", "rest@0:4+28"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Flags fields = %v; want %v", got, want)
	}
}

// A PDB whose GUID differs from the image is refused unless pdb_force names
// it; forcing also covers an image whose RSDS record was wiped. The forced
// load must carry a warning, since the PDB may describe another build.
func TestPDBForce(t *testing.T) {
	src := filepath.Join("testdata", "pdb", "fixture_x64.exe")
	img, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(img, []byte("RSDS"))
	if at < 0 {
		t.Fatal("fixture has no RSDS record")
	}
	pdbFile, _ := filepath.Abs(filepath.Join("testdata", "pdb", "fixture_x64.pdb"))
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	other := append([]byte(nil), img...)
	other[at+4] ^= 0xFF // GUID
	relinked := write("relinked.exe", other)
	wiped := append([]byte(nil), img...)
	copy(wiped[at:], "XXXX")
	stripped := write("stripped.exe", wiped)

	for _, c := range []struct {
		name, exe, pdb string
		force            bool
		used             bool
		note             string
	}{
		{"mismatch refused", relinked, pdbFile, false, false, "pass pdb_force=true"},
		{"mismatch forced", relinked, pdbFile, true, true, "GUID does not match"},
		{"no RSDS refused", stripped, pdbFile, false, false, "pdb_force=true"},
		{"no RSDS forced", stripped, pdbFile, true, true, "GUID does not match"},
		{"matching unaffected", src, pdbFile, true, true, ""},
	} {
		tg, err := loadDecompileTarget(c.exe, c.pdb, c.force)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if used := tg.pdb != ""; used != c.used {
			t.Errorf("%s: PDB used = %v; want %v (note %q)", c.name, used, c.used, tg.pdbNote)
		}
		if c.note == "" && tg.pdbNote != "" || !strings.Contains(tg.pdbNote, c.note) {
			t.Errorf("%s: note %q; want it to contain %q", c.name, tg.pdbNote, c.note)
		}
		if c.used && tg.host.debug == nil {
			t.Errorf("%s: PDB debug info not applied", c.name)
		}
	}
}
