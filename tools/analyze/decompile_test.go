package analyze

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestDecompileFixtureEntry(t *testing.T) {
	out, err := opDecompile(context.Background(), AnalyzeInput{FilePath: testBinary, VA: "entry, 0x1", MaxOutputChars: 100000})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Decompiled 1/2 function(s)",
		"PE x64, x86:LE:64:default:windows",
		"// entry @ 0x",
		"0x1: input error: 0x1 is not inside an executable section",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
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
	out, err := opDecompile(ctx, AnalyzeInput{FilePath: testBinary, VA: "entry"})
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
