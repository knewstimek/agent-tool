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
	"time"
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

// DWARF bitfields (here gcc's DWARF in a MinGW PE) become field accesses.
func TestDecompileDWARFBitfields(t *testing.T) {
	gcc, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc not found")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "bf.c")
	code := "struct Flags { unsigned int ready : 1; unsigned int mode : 3; int level : 4; unsigned int rest : 24; };\n" +
		"__attribute__((noinline)) int get_mode(struct Flags *f) { return f->mode; }\n" +
		"__attribute__((noinline)) int get_level(struct Flags *f) { return f->level; }\n" +
		"int main(void) { struct Flags f = {0}; return get_mode(&f) + get_level(&f); }\n"
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bf.exe")
	if out, err := exec.Command(gcc, "-g", "-O2", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("gcc cannot build here: %v\n%s", err, out)
	}
	out, err := opDecompile(context.Background(), AnalyzeInput{FilePath: bin, VA: "get_mode, get_level", MaxOutputChars: 100000})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"return f->mode;", "return f->level;"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
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

// A worker stays loaded for the next request on the same binary; a killed
// one leaves the pool and the next request starts a fresh worker.
func TestDecompileWorkerReuse(t *testing.T) {
	exe := filepath.Join("testdata", "pdb", "fixture_x64.exe")
	run := func(ctx context.Context) string {
		out, err := opDecompile(ctx, AnalyzeInput{FilePath: exe, VA: "use_node", MaxOutputChars: 100000})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	first := run(context.Background())
	if !strings.Contains(first, "Decompiled 1/1") {
		t.Fatalf("first call failed:\n%s", first)
	}
	second := run(context.Background())
	if !strings.Contains(second, "Decompiled 1/1") || !strings.Contains(second, "binary already loaded") {
		t.Fatalf("second call did not reuse the worker:\n%s", second)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	run(ctx) // kills the worker (or finishes first)
	third := run(context.Background())
	if !strings.Contains(third, "Decompiled 1/1") {
		t.Fatalf("call after a cancel failed:\n%s", third)
	}
	decompPool.mu.Lock()
	n := len(decompPool.workers)
	decompPool.mu.Unlock()
	if n > decompilePoolSize {
		t.Errorf("%d workers pooled, at most %d", n, decompilePoolSize)
	}
}

// An idle worker exits and leaves the pool after decompileIdle.
func TestDecompileIdleWorkerRetires(t *testing.T) {
	saved := decompileIdle
	decompileIdle = 300 * time.Millisecond
	defer func() { decompileIdle = saved }()
	exe := filepath.Join("testdata", "pdb", "fixture_x86.exe")
	if out, err := opDecompile(context.Background(), AnalyzeInput{FilePath: exe, VA: "entry"}); err != nil || !strings.Contains(out, "Decompiled 1/1") {
		t.Fatalf("decompile failed: %v\n%s", err, out)
	}
	decompPool.mu.Lock()
	var w *decompWorker
	for _, o := range decompPool.workers {
		if strings.HasPrefix(o.key, exe+"|") {
			w = o
		}
	}
	decompPool.mu.Unlock()
	if w == nil {
		t.Fatal("worker not pooled")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		decompPool.mu.Lock()
		pooled := false
		for _, o := range decompPool.workers {
			pooled = pooled || o == w
		}
		decompPool.mu.Unlock()
		if !pooled && w.cmd.ProcessState != nil {
			return // retired and reaped
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("idle worker was not retired and reaped")
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
