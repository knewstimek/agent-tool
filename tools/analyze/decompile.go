package analyze

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
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

	assume, err := parseAssumeBranches(input.AssumeBranches)
	if err != nil {
		return "", err
	}
	req := decompileRequest{Path: input.FilePath, Targets: targets, MemLimitMB: decompileMemLimitMB, PDBPath: input.PDBPath, PDBForce: input.PDBForce, AssumeBranches: assume}
	start := time.Now()
	lines, failure := runDecompileWorkerResuming(ctx, req, time.Duration(timeout)*time.Second)
	input.annotations, input.annotationNotice, err = loadFunctionAnnotations(ctx, input, lines)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		input.annotations, input.annotationNotice = nil, annotationLoadWarning(err)
	}
	return formatDecompile(input, targets, lines, failure, time.Since(start)), nil
}

// decompileRunner is the worker round trip; tests replace it.
var decompileRunner = runDecompileWorker

// runDecompileWorkerResuming runs the request and, when one function kills
// the worker (memory limit, crash), sends the functions it never reached to a
// fresh worker within the same time budget: one pathological function must
// not cost the results of the others in the call.
func runDecompileWorkerResuming(ctx context.Context, req decompileRequest, timeout time.Duration) ([]decompileLine, string) {
	deadline := time.Now().Add(timeout)
	lines, failure := decompileRunner(ctx, req, timeout)
	for {
		done := map[string]bool{}
		killed := false
		for _, l := range lines {
			if (l.Kind == "result" || l.Kind == "fatal") && l.Target != "" {
				done[l.Target] = true
				killed = killed || l.Kind == "fatal"
			}
		}
		var rest []string
		for _, t := range req.Targets {
			if !done[t] {
				rest = append(rest, t)
			}
		}
		left := time.Until(deadline)
		if !killed || len(rest) == 0 || left <= 0 || ctx.Err() != nil {
			return lines, failure
		}
		next := req
		next.Targets = rest
		more, f := decompileRunner(ctx, next, left)
		progress := false
		for _, l := range more {
			if l.Kind == "load" {
				continue // the first load line describes the binary
			}
			lines = append(lines, l)
			progress = progress || l.Target != ""
		}
		failure = f
		if !progress {
			return lines, failure
		}
	}
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
	if input.annotationNotice != "" {
		fmt.Fprintf(&sb, "// %s\n", input.annotationNotice)
	}
	var load *decompileLine
	results := map[string]decompileLine{}
	fatals := map[string]decompileLine{}
	var fatal *decompileLine
	for i := range lines {
		switch lines[i].Kind {
		case "load":
			if load == nil {
				load = &lines[i]
			}
		case "result":
			results[lines[i].Target] = lines[i]
		case "fatal":
			fatal = &lines[i]
			if lines[i].Target != "" {
				fatals[lines[i].Target] = lines[i]
			}
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
		fmt.Fprintf(&sb, "Debug info: %s (function names, prototypes, struct/enum types, global data and named locals applied). The structs/enums each function names follow it with member offsets and enum values; analyze type_info type_name=<T> prints any other.\n", load.PDB)
		if load.PDBNote != "" {
			fmt.Fprintf(&sb, "WARNING: PDB %s.\n", load.PDBNote)
		}
	} else {
		if load.PDBNote != "" {
			fmt.Fprintf(&sb, "PDB: %s.\n", load.PDBNote)
		}
		sb.WriteString("No debug types or prototypes are applied: parameter/local types and callee signatures are inferred by the decompiler (Ghidra-equivalent core), so treat names like param_1/local_10 and undefined types as recovered, not declared.\n")
	}

	if assume, _ := parseAssumeBranches(input.AssumeBranches); len(assume) != 0 {
		used := map[uint64]bool{}
		for _, r := range results {
			for _, a := range r.Assumed {
				used[a] = true
			}
		}
		var unused []uint64
		for a := range assume {
			if !used[a] {
				unused = append(unused, a)
			}
		}
		if len(unused) != 0 {
			sort.Slice(unused, func(i, j int) bool { return unused[i] < unused[j] })
			fmt.Fprintf(&sb, "WARNING: assume_branches not applied at %s: no decompiled flow reached a conditional jump there (check the address with disassemble).\n", hexList(unused))
		}
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
			if len(r.Bounded) != 0 {
				var parts []string
				for _, b := range r.Bounded {
					parts = append(parts, fmt.Sprintf("0x%x-0x%x", b[0], b[1]))
				}
				fmt.Fprintf(&sb, "// note: the whole-space flow exceeded the instruction limit (junk bytes behind opaque predicates), so flow was limited to the function's .pdata extent %s; each exit is marked \"Function flow out of bounds\" + halt_missing(). Code inside the extent may still include junk paths (halt_baddata); a runtime trace plus assume_branches removes them\n", strings.Join(parts, ", "))
			}
			if len(r.Assumed) != 0 {
				fmt.Fprintf(&sb, "// note: assume_branches applied at %s; the C below omits the other side of each\n", hexList(r.Assumed))
			}
			for _, w := range r.Warnings {
				fmt.Fprintf(&sb, "// warning: %s\n", w)
			}
			sb.WriteString(renderAnnotatedC(r.C, input.annotations[fmt.Sprintf("%016x", r.Entry)], input.LineNumbers))
			if r.Types != "" {
				fmt.Fprintf(&sb, "// types named above (from %s):\n%s", load.PDB, r.Types)
			}
		case have:
			fmt.Fprintf(&sb, "// %s: %s error: %s\n", t, r.ErrorKind, r.Error)
			if s := decompileSuggestion(r.ErrorKind, t); s != "" {
				sb.WriteString("// " + s + "\n")
			}

		case fatals[t].Kind != "":
			f := fatals[t]
			fmt.Fprintf(&sb, "// %s: %s error: %s\n", t, f.ErrorKind, f.Error)
			if s := decompileSuggestion(f.ErrorKind, t); s != "" {
				sb.WriteString("// " + s + "\n")
			}
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

	// The worker keeps the binary loaded, so continuing with result_offset
	// re-decompiles in well under a second: a function larger than the
	// output cap can still be read whole.
	return pageOutput(sb.String(), input.ResultOffset, input.MaxOutputChars, "decompile")
}

func decompileSuggestion(kind, target string) string {
	switch kind {
	case "input":
		if _, err := parseHexAddr(target); err != nil {
			return "" // a name: the error lists the candidates
		}
		return "Try: analyze function_at va=" + target + " to find the function start, or pe_info/elf_info for symbols"
	case "flow":
		return "The control flow from this entry is too large to decompile. Many paths ending at undecodable bytes mean junk bytes behind opaque predicates (obfuscation). Read the real path with analyze disassemble va=" + target + "; once a runtime trace or the disassembly confirms which side a remaining conditional jump takes, pass assume_branches=\"0x...=taken,0x...=fallthrough\""
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
