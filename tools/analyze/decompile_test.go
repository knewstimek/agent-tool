package analyze

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDecompileFixtureEntry(t *testing.T) {
	// The fixture is a Go program: Go ABI spec, DWARF names and types.
	out, err := opDecompile(context.Background(), AnalyzeInput{FilePath: testBinary, VA: "main.main, 0x1", MaxOutputChars: 100000})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Decompiled 1/2 function(s)",
		"PE x64, x86:LE:64:default:golang",
		"Debug info: DWARF (embedded)",
		"// main.main @ 0x",
		"0x1: input error: 0x1 is not inside an executable section",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// A Go-built ELF carries DWARF: parameter names and types, Go's result
// convention (results recorded as ~r0 parameters) and the Go ABI must all
// come through -- registers on amd64, stack slots for arguments and results
// on 386.
func TestDecompileGoELFWithDWARF(t *testing.T) {
	for _, c := range []struct {
		goarch string
		want   []string
	}{
		{"amd64", []string{
			"ELF x64, x86:LE:64:default:golang",
			"long main.addMul(long a, long b)",
			"return (a + b) * 3;",
			"main.addMul(os_Args.len, 2)",
		}},
		{"386", []string{
			"ELF x86, x86:LE:32:default:golang",
			"int main.addMul(int a, int b)",
			"= (b + a) * 3;",
			" = main.addMul(os_Args.len, 2);",
		}},
	} {
		t.Run(c.goarch, func(t *testing.T) {
			out := decompileGoProgram(t, c.goarch)
			for _, want := range append(c.want, "Debug info: DWARF (embedded)") {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
		})
	}
}

func decompileGoProgram(t *testing.T, goarch string) string {
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	code := "package main\n\nimport \"os\"\n\n//go:noinline\nfunc addMul(a, b int) int { return (a + b) * 3 }\n\nfunc main() { os.Exit(addMul(len(os.Args), 2)) }\n"
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module m\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "prog.elf")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, err := opDecompile(context.Background(), AnalyzeInput{FilePath: bin, VA: "main.addMul, main.main", MaxOutputChars: 100000})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDecompileRequiresVA(t *testing.T) {
	if _, err := opDecompile(context.Background(), AnalyzeInput{FilePath: testBinary}); err == nil || !strings.Contains(err.Error(), "va is required") {
		t.Fatalf("err = %v", err)
	}
	var many []string
	for i := 0; i <= decompileMaxTargets; i++ {
		many = append(many, fmt.Sprintf("0x%x", 0x1000+i))
	}
	if _, err := opDecompile(context.Background(), AnalyzeInput{FilePath: testBinary, VA: strings.Join(many, ",")}); err == nil {
		t.Fatal("accepted more than decompileMaxTargets targets")
	}
	if _, err := opDecompile(context.Background(), AnalyzeInput{FilePath: testBinary, VA: "entry", TimeoutSec: decompileMaxTimeout + 1}); err == nil {
		t.Fatal("accepted timeout_sec above the maximum")
	}
}

func TestDecompileCancelledContextKillsWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := opDecompile(ctx, AnalyzeInput{FilePath: testBinary, VA: "main.main"})
	if err != nil {
		t.Fatal(err)
	}
	// The worker may finish before the cancellation is noticed; either way
	// opDecompile must return a report, not hang.
	if !strings.Contains(out, "cancelled by the client") && !strings.Contains(out, "Decompiled 1/1") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestSplitTargets(t *testing.T) {
	got := splitTargets(" 0x10, main;0x10\n0x20 ")
	if want := []string{"0x10", "main", "0x20"}; !reflect.DeepEqual(got, want) {
		t.Errorf("splitTargets = %q, want %q", got, want)
	}
}

// A worker that died mid-batch reports which target it was on, and the
// targets after it are listed as not decompiled.
func TestFormatDecompileWorkerDeath(t *testing.T) {
	lines := []decompileLine{
		{Kind: "load", Format: "PE x64", Spec: "x86:LE:64:default:windows"},
		{Kind: "result", Target: "0x10", Entry: 0x10, Name: "FUN_00000010", C: "void FUN_00000010(void) {\n}\n"},
		{Kind: "fatal", Target: "0x20", ErrorKind: "memory", Error: "decompiler heap reached 2049 MB (limit 2048 MB)"},
	}
	out := formatDecompile(AnalyzeInput{FilePath: "x.exe"}, []string{"0x10", "0x20", "0x30"}, lines, "", 0)
	for _, want := range []string{
		"Decompiled 1/3",
		"// 0x20: memory error: decompiler heap reached",
		"// 0x30: not decompiled: worker stopped while decompiling 0x20",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}
