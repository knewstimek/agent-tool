package analyze

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"sync"
	"time"
)

// DecompileAllArg is the CLI subcommand that decompiles every known
// function of a binary to a JSONL corpus. A whole binary takes minutes, too
// long for one MCP call, so it is a command an agent runs in the background
// (or a person runs directly) and then reads the file.
const DecompileAllArg = "decompile-all"

// corpusEntry is one line of the corpus file.
type corpusEntry struct {
	Entry string  `json:"entry"` // hex VA
	Name  string  `json:"name,omitempty"`
	C     string  `json:"c,omitempty"`
	Error string  `json:"error,omitempty"`
	Secs  float64 `json:"secs,omitempty"`
}

// RunDecompileAll is the decompile-all subcommand. It returns the exit code.
func RunDecompileAll(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet(DecompileAllArg, flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("o", "", "output JSONL file (default <binary>.decompiled.jsonl); an existing file is resumed")
	jobs := fs.Int("j", analysisThreads(), "worker processes")
	perFunc := fs.Int("timeout", 30, "seconds allowed per function")
	pdbPath := fs.String("pdb", "", "PDB path, or none (PE only)")
	limit := fs.Int("limit", 0, "decompile at most this many functions (0 = all)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: agent-tool %s [flags] <binary>\n\nDecompiles every known function of an x86/x64 PE/ELF binary to C, one JSON\nobject per line: {\"entry\",\"name\",\"c\"} or {\"entry\",\"error\"}.\n\n", DecompileAllArg)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || *jobs < 1 || *perFunc < 1 {
		fs.Usage()
		return 2
	}
	bin := fs.Arg(0)
	if *out == "" {
		*out = bin + ".decompiled.jsonl"
	}

	// The function list is the decompile host's known starts (with PDB or
	// DWARF functions); the analysis cache makes this load cheap.
	t, err := loadDecompileTarget(bin, *pdbPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	starts := append([]uint64(nil), t.host.starts...)
	t = nil

	done, err := readCorpusEntries(*out)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	var todo []uint64
	for _, va := range starts {
		if !done[va] {
			todo = append(todo, va)
		}
	}
	if *limit > 0 && len(todo) > *limit {
		todo = todo[:*limit]
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	fmt.Fprintf(stderr, "%s: %d functions, %d already in %s, %d to go, %d workers\n",
		bin, len(starts), len(done), *out, len(todo), *jobs)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var mu sync.Mutex
	written, failed := 0, 0
	write := func(e corpusEntry) {
		mu.Lock()
		defer mu.Unlock()
		line, _ := json.Marshal(e)
		w.Write(append(line, '\n'))
		written++
		if e.Error != "" {
			failed++
		}
		if written%500 == 0 {
			w.Flush()
			fmt.Fprintf(stderr, "%d/%d (%d failed)\n", written, len(todo), failed)
		}
	}

	// Workers take batches; a batch that times out keeps the functions that
	// finished, records the one that was running and requeues the rest.
	// Batches go out largest functions first, a large function alone: a few
	// big functions take most of the time, and left to the end of an
	// address-ordered queue they ran one after another on one worker while
	// the others sat idle (longest-processing-time-first scheduling).
	batches := corpusBatches(todo, starts)
	queue := make(chan []uint64, len(batches)+len(todo))
	for _, b := range batches {
		queue <- b
	}
	var pending sync.WaitGroup
	pending.Add(len(todo))
	go func() { pending.Wait(); close(queue) }()
	var wg sync.WaitGroup
	start := time.Now()
	for range *jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for vas := range queue {
				if ctx.Err() != nil {
					pending.Add(-len(vas))
					continue
				}
				n := corpusBatch(ctx, bin, *pdbPath, vas, *perFunc, write)
				pending.Add(-n)
				if rest := vas[n:]; len(rest) > 0 {
					queue <- rest
				}
			}
		}()
	}
	wg.Wait()
	w.Flush()
	fmt.Fprintf(stderr, "done: %d written (%d failed) in %s -> %s\n", written, failed, time.Since(start).Round(time.Second), *out)
	if ctx.Err() != nil {
		return 130
	}
	return 0
}

// corpusBatch decompiles vas on a pooled worker, writing an entry for each
// function settled, and returns how many were (a prefix of vas).
func corpusBatch(ctx context.Context, bin, pdbPath string, vas []uint64, perFunc int, write func(corpusEntry)) int {
	targets := make([]string, len(vas))
	for i, va := range vas {
		targets[i] = fmt.Sprintf("0x%x", va)
	}
	req := decompileRequest{Path: bin, PDBPath: pdbPath, Targets: targets, MemLimitMB: decompileMemLimitMB}
	lines, failure := runDecompileWorker(ctx, req, time.Duration(perFunc*len(vas))*time.Second)
	n := 0
	for _, l := range lines {
		if l.Kind != "result" || n >= len(vas) {
			continue
		}
		e := corpusEntry{Entry: targets[n], Name: l.Name, C: l.C, Secs: l.Secs}
		if l.Error != "" {
			e.Error = l.ErrorKind + ": " + l.Error
		}
		write(e)
		n++
	}
	if n < len(vas) && ctx.Err() == nil {
		if failure != "" {
			// The function that was running when the worker died or timed out.
			write(corpusEntry{Entry: targets[n], Error: failure})
			return n + 1
		}
		// Results missing without a failure: the worker reported a fatal
		// error for the whole request (the binary did not load). Retrying
		// would loop, so the rest are recorded with that error.
		msg := "no result from the decompile worker"
		for _, l := range lines {
			if l.Kind == "fatal" {
				msg = l.ErrorKind + ": " + l.Error
			}
		}
		for ; n < len(vas); n++ {
			write(corpusEntry{Entry: targets[n], Error: msg})
		}
	}
	return n
}

// readCorpusEntries is the set of functions an existing corpus file holds.
func readCorpusEntries(path string) (map[uint64]bool, error) {
	done := map[uint64]bool{}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return done, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 256<<20)
	for sc.Scan() {
		var e corpusEntry
		var va uint64
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			if _, err := fmt.Sscanf(e.Entry, "0x%x", &va); err == nil {
				done[va] = true
			}
		}
	}
	return done, nil
}

// corpusBatches groups vas, largest first, into batches of at most 32
// functions and about 8 KB of code; a function's size is the distance to
// the next known start.
func corpusBatches(vas, starts []uint64) [][]uint64 {
	size := func(va uint64) uint64 {
		i := sort.Search(len(starts), func(i int) bool { return starts[i] > va })
		if i == len(starts) {
			return 4096
		}
		return min(starts[i]-va, 1<<20)
	}
	sorted := append([]uint64(nil), vas...)
	sizes := make(map[uint64]uint64, len(sorted))
	for _, va := range sorted {
		sizes[va] = size(va)
	}
	sort.SliceStable(sorted, func(i, j int) bool { return sizes[sorted[i]] > sizes[sorted[j]] })
	var out [][]uint64
	var cur []uint64
	var bytes uint64
	for _, va := range sorted {
		if len(cur) > 0 && (len(cur) == 32 || bytes+sizes[va] > 8192) {
			out = append(out, cur)
			cur, bytes = nil, 0
		}
		cur = append(cur, va)
		bytes += sizes[va]
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}
