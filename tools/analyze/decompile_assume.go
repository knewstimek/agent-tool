package analyze

import (
	"fmt"
	"strings"

	"github.com/knewstimek/gosleigh/pkg/ext/branchassume"
)

const maxAssumeBranches = 256

// parseAssumeBranches reads assume_branches: "0x401a2c=taken, 0x401b10=fallthrough".
func parseAssumeBranches(s string) (map[uint64]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	out := map[uint64]string{}
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' }) {
		addr, dir, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("assume_branches entry %q: write <hex address>=taken or <hex address>=fallthrough", item)
		}
		va, err := parseHexAddr(strings.TrimSpace(addr))
		if err != nil {
			return nil, fmt.Errorf("assume_branches entry %q: address must be hex (0x401a2c): %v", item, err)
		}
		switch d := strings.ToLower(strings.TrimSpace(dir)); d {
		case "taken", "fallthrough":
			if prev, dup := out[va]; dup && prev != d {
				return nil, fmt.Errorf("assume_branches: 0x%x is given both %s and %s", va, prev, d)
			}
			out[va] = d
		default:
			return nil, fmt.Errorf("assume_branches entry %q: direction must be taken or fallthrough", item)
		}
	}
	if len(out) > maxAssumeBranches {
		return nil, fmt.Errorf("assume_branches: %d entries, at most %d", len(out), maxAssumeBranches)
	}
	return out, nil
}

func assumeDirections(m map[uint64]string) map[uint64]branchassume.Direction {
	if len(m) == 0 {
		return nil
	}
	out := make(map[uint64]branchassume.Direction, len(m))
	for va, d := range m {
		if d == "taken" {
			out[va] = branchassume.Taken
		} else {
			out[va] = branchassume.Fallthrough
		}
	}
	return out
}

func hexList(vas []uint64) string {
	parts := make([]string, len(vas))
	for i, va := range vas {
		parts[i] = fmt.Sprintf("0x%x", va)
	}
	return strings.Join(parts, ", ")
}
