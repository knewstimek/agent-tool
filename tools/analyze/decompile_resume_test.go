package analyze

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A function that kills the worker costs only its own result: the functions
// it never reached go to a fresh worker.
func TestDecompileResumesAfterWorkerDeath(t *testing.T) {
	var calls [][]string
	defer func(r func(context.Context, decompileRequest, time.Duration) ([]decompileLine, string)) {
		decompileRunner = r
	}(decompileRunner)
	decompileRunner = func(_ context.Context, req decompileRequest, _ time.Duration) ([]decompileLine, string) {
		calls = append(calls, req.Targets)
		lines := []decompileLine{{Kind: "load", Format: "PE x64", Spec: "x86:LE:64:default:windows"}}
		for _, tg := range req.Targets {
			if tg == "0x20" {
				return append(lines, decompileLine{Kind: "fatal", Target: tg, ErrorKind: "memory", Error: "decompiler heap reached 2049 MB (limit 2048 MB)"}), ""
			}
			lines = append(lines, decompileLine{Kind: "result", Target: tg, Name: "f" + tg, C: "void f(void) {\n}\n"})
		}
		return lines, ""
	}
	targets := []string{"0x10", "0x20", "0x30"}
	lines, failure := runDecompileWorkerResuming(context.Background(), decompileRequest{Targets: targets}, time.Minute)
	if len(calls) != 2 || strings.Join(calls[1], ",") != "0x30" {
		t.Fatalf("worker calls = %v, want a second call for 0x30 only", calls)
	}
	out := formatDecompile(AnalyzeInput{FilePath: "x.exe"}, targets, lines, failure, 0)
	for _, want := range []string{"Decompiled 2/3", "// 0x20: memory error: decompiler heap reached", "// f0x30 @"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "worker stopped") {
		t.Errorf("0x30 reported as lost:\n%s", out)
	}
}
