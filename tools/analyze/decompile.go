package analyze

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	// decompileMemLimitMB is the worker's heap limit, the same per-function
	// limit the decompiler's real-binary measurement runs with.
	decompileMemLimitMB = 2048
	// decompileJobHeadroomMB lets the worker's own watchdog report the
	// blow-up before the OS limit kills it silently.
	decompileJobHeadroomMB  = 1024
	decompileDefaultTimeout = 60
	decompileMaxTimeout     = 600
	decompileMaxTargets     = 16
)

// opDecompile decompiles functions to C in a child worker process (see
// DecompileWorkerArg) and formats the results.
func opDecompile(ctx context.Context, input AnalyzeInput) (string, error) {
	targets := splitTargets(input.VA)
	if len(targets) == 0 {
		return "", fmt.Errorf("va is required: a function address in hex (0x140001000) or a symbol name; separate up to %d with commas", decompileMaxTargets)
	}
	if len(targets) > decompileMaxTargets {
		return "", fmt.Errorf("%d functions requested, at most %d per call; split the list", len(targets), decompileMaxTargets)
	}
	timeout := input.TimeoutSec
	if timeout <= 0 {
		timeout = decompileDefaultTimeout
	}
	if timeout > decompileMaxTimeout {
		return "", fmt.Errorf("timeout_sec must be at most %d", decompileMaxTimeout)
	}

	req := decompileRequest{Path: input.FilePath, Targets: targets, MemLimitMB: decompileMemLimitMB, PDBPath: input.PDBPath, PDBForce: input.PDBForce}
	start := time.Now()
	lines, failure := runDecompileWorker(ctx, req, time.Duration(timeout)*time.Second)
	return formatDecompile(input, targets, lines, failure, time.Since(start)), nil
}

func splitTargets(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' }) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func hasFatal(lines []decompileLine) bool {
	for _, l := range lines {
		if l.Kind == "fatal" {
			return true
		}
	}
	return false
}

func formatDecompile(input AnalyzeInput, targets []string, lines []decompileLine, failure string, elapsed time.Duration) string {
	var sb strings.Builder
	var load *decompileLine
	results := map[string]decompileLine{}
	var fatal *decompileLine
	for i := range lines {
		switch lines[i].Kind {
		case "load":
			load = &lines[i]
		case "result":
			results[lines[i].Target] = lines[i]
		case "fatal":
			fatal = &lines[i]
		}
	}

	base := filepath.Base(input.FilePath)
	if load == nil {
		msg := failure
		if fatal != nil {
			msg = fatal.Error
		}
		fmt.Fprintf(&sb, "decompile failed to load %s: %s\n", base, msg)
		sb.WriteString("Fallback: analyze disassemble va=<addr> stop_at_ret=true\n")
		return sb.String()
	}

	ok := 0
	for _, r := range results {
		if r.Error == "" {
			ok++
		}
	}
	cached := ""
	if load.Reused {
		cached = ", binary already loaded"
	}
	fmt.Fprintf(&sb, "Decompiled %d/%d function(s) from %s (%s, %s) in %.1fs%s\n", ok, len(targets), base, load.Format, load.Spec, elapsed.Seconds(), cached)
	fmt.Fprintf(&sb, "Host info from the file: %d known function starts (%d named), %d imports", load.KnownStarts, load.NamedStarts, load.Imports)
	if load.HostTracked != "" {
		fmt.Fprintf(&sb, ", %s", load.HostTracked)
	}
	sb.WriteString(".\n")
	if load.PDB != "" {
		fmt.Fprintf(&sb, "Debug info: %s (function names, prototypes, struct/enum types, global data and named locals applied).\n", load.PDB)
		if load.PDBNote != "" {
			fmt.Fprintf(&sb, "WARNING: PDB %s.\n", load.PDBNote)
		}
	} else {
		if load.PDBNote != "" {
			fmt.Fprintf(&sb, "PDB: %s.\n", load.PDBNote)
		}
		sb.WriteString("No debug types or prototypes are applied: parameter/local types and callee signatures are inferred by the decompiler (Ghidra-equivalent core), so treat names like param_1/local_10 and undefined types as recovered, not declared.\n")
	}

	for _, t := range targets {
		r, have := results[t]
		sb.WriteString("\n")
		switch {
		case have && r.Error == "":
			fmt.Fprintf(&sb, "// %s @ 0x%x (%.2fs)\n", r.Name, r.Entry, r.Secs)
			if r.Note != "" {
				fmt.Fprintf(&sb, "// note: %s\n", r.Note)
			}
			for _, w := range r.Warnings {
				fmt.Fprintf(&sb, "// warning: %s\n", w)
			}
			sb.WriteString(strings.TrimLeft(r.C, "\n"))
			if !strings.HasSuffix(r.C, "\n") {
				sb.WriteString("\n")
			}
		case have:
			fmt.Fprintf(&sb, "// %s: %s error: %s\n", t, r.ErrorKind, r.Error)
			sb.WriteString("// " + decompileSuggestion(r.ErrorKind, t) + "\n")
		case fatal != nil && fatal.Target == t:
			fmt.Fprintf(&sb, "// %s: %s error: %s\n", t, fatal.ErrorKind, fatal.Error)
			sb.WriteString("// " + decompileSuggestion(fatal.ErrorKind, t) + "\n")
		default:
			reason := failure
			if fatal != nil {
				reason = fmt.Sprintf("worker stopped while decompiling %s (%s)", fatal.Target, fatal.Error)
			}
			if reason == "" {
				reason = "no result from the worker"
			}
			fmt.Fprintf(&sb, "// %s: not decompiled: %s\n", t, reason)
			sb.WriteString("// " + decompileSuggestion("timeout", t) + "\n")
		}
	}

	out := sb.String()
	if max := input.MaxOutputChars; max > 0 && len([]rune(out)) > max {
		out = string([]rune(out)[:max]) + fmt.Sprintf("\n... [truncated at %d chars; decompile fewer functions per call or raise max_output_chars]\n", max)
	}
	return out
}

func decompileSuggestion(kind, target string) string {
	switch kind {
	case "input":
		return "Try: analyze function_at va=" + target + " to find the function start, or pe_info/elf_info for symbols"
	case "memory", "timeout":
		return "Try: decompile it alone with a larger timeout_sec, or analyze disassemble va=" + target + " stop_at_ret=true"
	default:
		return "This is a decompiler engine failure on this input. Fallback: analyze disassemble va=" + target + " stop_at_ret=true"
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(line)
}

// limitedBuffer keeps the first 8 KB of the worker's stderr (a Go runtime
// crash dump can be megabytes).
type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := 8<<10 - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}
