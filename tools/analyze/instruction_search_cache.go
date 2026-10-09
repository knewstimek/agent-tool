package analyze

import (
	"sync"

	"agent-tool/common"
)

// searchBinary is a binary prepared for instruction_search: its function
// table and the instructions its functions reach. Building it is most of a
// search on a large image (open, sweep, PDB names, a decode of every
// function), and an agent usually searches one binary several times in a
// row, so the last one is kept in memory until the file changes or the
// server goes idle.
type searchBinary struct {
	bin                  *cgBinary
	reachable, interiors *rvaBits
	complete             bool
}

var searchCache struct {
	mu    sync.Mutex
	key   string
	entry *searchBinary
}

func init() {
	common.OnIdleRelease(func() {
		searchCache.mu.Lock()
		searchCache.key, searchCache.entry = "", nil
		searchCache.mu.Unlock()
	})
}

func loadSearchBinary(path string) (*searchBinary, error) {
	key := fileIdentity(path)
	searchCache.mu.Lock()
	defer searchCache.mu.Unlock()
	if key != "" && key == searchCache.key {
		return searchCache.entry, nil
	}
	bin, err := cgOpenBinary(path)
	if err != nil {
		return nil, err
	}
	if bin.closer != nil {
		bin.closer() // section bytes are already in memory
	}
	sb := &searchBinary{bin: bin}
	if bin.arch == "x86" || bin.arch == "x64" {
		sb.reachable, sb.interiors, sb.complete = analyzeInstructionReachability(bin)
	}
	searchCache.key, searchCache.entry = key, sb
	return sb, nil
}
