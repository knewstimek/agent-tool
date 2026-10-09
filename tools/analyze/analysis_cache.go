package analyze

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sort"
	"sync"
	"time"
)

// The analysis cache keeps whole-binary results that are expensive to
// derive and fixed for a given file -- the starts a linear sweep finds, the
// call sites the non-returning discovery walks -- under the user cache
// directory, so a later process (a new session, a retired worker) skips
// the work. The key covers the file (path, size, mtime) and the agent-tool
// executable itself, so a rebuilt binary or a new agent-tool version never
// reads an older result. AGENT_TOOL_NO_ANALYSIS_CACHE=1 turns it off.

const analysisCacheMax = 256 // entries kept; the oldest go first

var analysisCacheDir = sync.OnceValue(func() string {
	if os.Getenv("AGENT_TOOL_NO_ANALYSIS_CACHE") != "" {
		return ""
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(base, "agent-tool", "analysis")
	if os.MkdirAll(dir, 0o700) != nil {
		return ""
	}
	return dir
})

// toolIdentity is the running executable's size and mtime.
var toolIdentity = sync.OnceValue(func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	fi, err := os.Stat(exe)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d|%d", fi.Size(), fi.ModTime().UnixNano())
})

// fileIdentity is a file's absolute path, size and mtime ("" when unknown).
func fileIdentity(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s|%d|%d", abs, fi.Size(), fi.ModTime().UnixNano())
}

// analysisCachePath is the cache file for a key, or "" when caching is off
// or the inputs cannot be identified.
func analysisCachePath(parts ...string) string {
	dir, tool := analysisCacheDir(), toolIdentity()
	if dir == "" || tool == "" {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(tool))
	for _, p := range parts {
		if p == "" {
			return ""
		}
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return filepath.Join(dir, hex.EncodeToString(h.Sum(nil)[:16])+".bin")
}

// loadUint64s reads a cached array; ok is false on any miss or damage.
func loadUint64s(path string) ([]uint64, bool) {
	if path == "" {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 8 {
		return nil, false
	}
	n := binary.LittleEndian.Uint64(data)
	if uint64(len(data)-8) != n*8 {
		return nil, false
	}
	out := make([]uint64, n)
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(data[8+8*i:])
	}
	_ = os.Chtimes(path, time.Now(), time.Now()) // recently used, kept longest
	return out, true
}

// storeUint64s writes a cached array (best effort) and trims the cache.
func storeUint64s(path string, vals []uint64) {
	if path == "" {
		return
	}
	data := make([]byte, 8+8*len(vals))
	binary.LittleEndian.PutUint64(data, uint64(len(vals)))
	for i, v := range vals {
		binary.LittleEndian.PutUint64(data[8+8*i:], v)
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) != nil || os.Rename(tmp, path) != nil {
		_ = os.Remove(tmp)
		return
	}
	trimAnalysisCache(filepath.Dir(path))
}

func trimAnalysisCache(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= analysisCacheMax {
		return
	}
	type entry struct {
		name string
		mod  int64
	}
	var es []entry
	for _, e := range entries {
		if fi, err := e.Info(); err == nil {
			es = append(es, entry{e.Name(), fi.ModTime().UnixNano()})
		}
	}
	sort.Slice(es, func(i, j int) bool { return es[i].mod < es[j].mod })
	for _, e := range es[:len(es)-analysisCacheMax] {
		_ = os.Remove(filepath.Join(dir, e.name))
	}
}

// hashUint64s fingerprints a sorted list (e.g. function starts) for a key.
func hashUint64s(vals []uint64) string {
	h := sha256.New()
	var b [8]byte
	for _, v := range vals {
		binary.LittleEndian.PutUint64(b[:], v)
		h.Write(b[:])
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// cachedSweepStarts is linearSweepStarts for a section of the file id,
// through the analysis cache.
func cachedSweepStarts(id string, data []byte, rva uint32, mode int) []uint32 {
	path := analysisCachePath("sweep", id, fmt.Sprintf("%x|%d|%d", rva, len(data), mode))
	if vals, ok := loadUint64s(path); ok {
		out := make([]uint32, len(vals))
		for i, v := range vals {
			out[i] = uint32(v)
		}
		return out
	}
	starts := linearSweepStarts(data, rva, mode)
	vals := make([]uint64, len(starts))
	for i, v := range starts {
		vals[i] = uint64(v)
	}
	storeUint64s(path, vals)
	return starts
}

// analysisThreads is how many goroutines a whole-binary scan uses. The
// default leaves most cores to the user (NumCPU/4, between 2 and 4);
// AGENT_TOOL_ANALYZE_THREADS sets it (decompile workers inherit it).
var analysisThreads = sync.OnceValue(func() int {
	if n, err := strconv.Atoi(os.Getenv("AGENT_TOOL_ANALYZE_THREADS")); err == nil && n > 0 {
		return min(n, 64)
	}
	return min(max(runtime.NumCPU()/4, 2), 4)
})
