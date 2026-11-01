package analyze

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestParseAssumeBranches(t *testing.T) {
	got, err := parseAssumeBranches(" 0x401a2c=taken, 0x401B10=Fallthrough;0x401a2c=taken ")
	if err != nil || len(got) != 2 || got[0x401a2c] != "taken" || got[0x401b10] != "fallthrough" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"0x401a2c", "0x401a2c=maybe", "zz=taken", "0x10=taken,0x10=fallthrough"} {
		if _, err := parseAssumeBranches(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// One side of the guard runs into bytes that are no instruction: plain, that
// path ends in halt_baddata(); with the branch fixed to the other side the
// junk is not decompiled at all, and the output says which branch was fixed.
func TestDecompileAssumeBranches(t *testing.T) {
	gcc, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc not found")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "junk.c")
	code := "__attribute__((noinline)) int guarded(int x) {\n" +
		"\tif (x > 0) return x * 3 + 1;\n" +
		"\t__asm__ volatile(\".byte 0x06, 0x06, 0x06\");\n" +
		"\treturn 0;\n}\n" +
		"int main(int argc, char **argv) { (void)argv; return guarded(argc); }\n"
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "junk.exe")
	if out, err := exec.Command(gcc, "-g", "-O2", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("gcc cannot build here: %v\n%s", err, out)
	}
	tg, err := loadDecompileTarget(bin, "none", false)
	if err != nil {
		t.Fatal(err)
	}
	entry, _, err := tg.resolve("guarded")
	if err != nil {
		t.Fatal(err)
	}
	jcc := uint64(0)
	for va, n := entry, 0; n < 16 && jcc == 0; n++ {
		code, ok := tg.codeAt(va)
		if !ok {
			t.Fatalf("no code at 0x%x", va)
		}
		inst, err := x86asm.Decode(code, 64)
		if err != nil {
			t.Fatalf("decode at 0x%x: %v", va, err)
		}
		if _, rel := inst.Args[0].(x86asm.Rel); rel && inst.Op != x86asm.JMP && inst.Op != x86asm.CALL {
			jcc = va
		}
		va += uint64(inst.Len)
	}
	if jcc == 0 {
		t.Fatal("no conditional jump in guarded")
	}

	decompile := func(assume string) string {
		out, err := opDecompile(context.Background(), AnalyzeInput{FilePath: bin, VA: "guarded", PDBPath: "none", AssumeBranches: assume, MaxOutputChars: 100000})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := decompile(""); !strings.Contains(out, "halt_baddata();") {
		t.Fatalf("plain decompile should halt on the junk path:\n%s", out)
	}
	clean := 0
	for _, dir := range []string{"taken", "fallthrough"} {
		out := decompile(fmt.Sprintf("0x%x=%s", jcc, dir))
		if !strings.Contains(out, fmt.Sprintf("assume_branches applied at 0x%x", jcc)) || !strings.Contains(out, "(assume_branches, not analysis)") {
			t.Errorf("%s: branch not reported as fixed:\n%s", dir, out)
		}
		if !strings.Contains(out, "halt_baddata") {
			clean++
			if !strings.Contains(out, "* 3") {
				t.Errorf("%s: the real path is missing:\n%s", dir, out)
			}
		}
	}
	if clean != 1 {
		t.Errorf("exactly one direction should drop the junk path, got %d", clean)
	}

	out := decompile("0x1=taken")
	if !strings.Contains(out, "assume_branches not applied at 0x1") {
		t.Errorf("unreached address not reported:\n%s", out)
	}
}
