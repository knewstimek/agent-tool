package codegraph

import (
	"context"
	"fmt"
	"unicode/utf8"
)

// SyntaxNode spans UTF-8 bytes in the exact decoded source passed to
// ParseSyntaxTree. Anonymous punctuation is retained, including missing tokens.
type SyntaxNode struct {
	Type                            string
	StartByte, EndByte              int
	Parent, FirstChild, NextSibling int
	Named, Missing, HasError        bool
}

// SyntaxTree is a detached snapshot: no WASM pointers/resources escape parsing.
type SyntaxTree struct {
	Language string
	Nodes    []SyntaxNode
}

const MaxSyntaxBytes = 8 * 1024 * 1024
const maxSyntaxNodes = 200000
const maxSyntaxDepth = 1024

// ParseSyntaxTree obtains the concrete C++/Python tree from the existing embedded
// engine, without an index, CGO, external processes or source-file writes.
func ParseSyntaxTree(ctx context.Context, language, source string) (tree *SyntaxTree, err error) {
	if language != "cpp" && language != "python" {
		return nil, fmt.Errorf("syntax trees support cpp and python")
	}
	if len(source) > MaxSyntaxBytes {
		return nil, fmt.Errorf("syntax source exceeds %d bytes", MaxSyntaxBytes)
	}
	if !utf8.ValidString(source) {
		return nil, fmt.Errorf("syntax source must be decoded UTF-8")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	e, err := getEngineContext(ctx, language)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			e.parseCount = maxParsesPerEngine
		}
		putEngine(e)
	}()
	e.parseCount++
	src, err := e.allocString(ctx, source)
	if err != nil {
		return nil, err
	}
	defer e.free(context.Background(), src)
	res, err := e.mod.ExportedFunction("ts_parser_parse_string").Call(ctx, e.parserPtr, 0, uint64(src), uint64(len(source)))
	if err != nil {
		return nil, fmt.Errorf("syntax parse: %w", err)
	}
	if len(res) == 0 || res[0] == 0 {
		return nil, fmt.Errorf("syntax parse returned no tree")
	}
	treePtr := res[0]
	defer e.mod.ExportedFunction("ts_tree_delete").Call(context.Background(), treePtr)
	// TSNode is a wasm32 by-value struct, passed through linear memory.
	scratch, err := e.allocBuf(ctx, (maxSyntaxDepth+1)*32)
	if err != nil {
		return nil, err
	}
	defer e.free(context.Background(), scratch)
	if _, err = e.mod.ExportedFunction("ts_tree_root_node").Call(ctx, uint64(scratch), treePtr); err != nil {
		return nil, err
	}
	tree = &SyntaxTree{Language: language}
	type frame struct{ index, count, next, lastChild int }
	stack := make([]frame, 0, 32)
	typeCache := make(map[uint32]string)
	value := func(name string, ptr uint64) (uint32, error) {
		r, callErr := e.mod.ExportedFunction(name).Call(ctx, ptr)
		if callErr != nil {
			return 0, callErr
		}
		return uint32(r[0]), nil
	}
	readString := func(ptr uint32) (string, error) {
		mem := e.mod.Memory()
		for size := uint32(0); size < 4096; size++ {
			b, ok := mem.ReadByte(ptr + size)
			if !ok {
				return "", fmt.Errorf("invalid syntax string pointer")
			}
			if b == 0 {
				data, _ := mem.Read(ptr, size)
				return string(data), nil
			}
		}
		return "", fmt.Errorf("syntax string exceeds limit")
	}
	add := func(depth, parent int) (frame, error) {
		if len(tree.Nodes) >= maxSyntaxNodes {
			return frame{}, fmt.Errorf("syntax tree exceeds %d nodes", maxSyntaxNodes)
		}
		ptr := uint64(scratch) + uint64(depth*32)
		start, callErr := value("ts_node_start_byte", ptr)
		if callErr != nil {
			return frame{}, callErr
		}
		end, callErr := value("ts_node_end_byte", ptr)
		if callErr != nil {
			return frame{}, callErr
		}
		if start > end || int(end) > len(source) {
			return frame{}, fmt.Errorf("invalid syntax span")
		}
		tp, callErr := value("ts_node_type", ptr)
		if callErr != nil {
			return frame{}, callErr
		}
		kind, ok := typeCache[tp]
		if !ok {
			kind, callErr = readString(tp)
			if callErr != nil {
				return frame{}, callErr
			}
			typeCache[tp] = kind
		}
		named, callErr := value("ts_node_is_named", ptr)
		if callErr != nil {
			return frame{}, callErr
		}
		count, callErr := value("ts_node_child_count", ptr)
		if callErr != nil {
			return frame{}, callErr
		}
		missing := false
		// The embedded ABI lacks ts_node_is_missing. Query the zero-width leaf's
		// S-expression to distinguish MISSING tokens from legitimate empty nodes.
		if start == end && count == 0 && parent >= 0 {
			sp, callErr := value("ts_node_string", ptr)
			if callErr != nil {
				return frame{}, callErr
			}
			s, readErr := readString(sp)
			e.free(ctx, sp)
			if readErr != nil {
				return frame{}, readErr
			}
			missing = len(s) >= 9 && s[:9] == "(MISSING "
		}
		index := len(tree.Nodes)
		tree.Nodes = append(tree.Nodes, SyntaxNode{Type: kind, StartByte: int(start), EndByte: int(end), Parent: parent, FirstChild: -1, NextSibling: -1, Named: named != 0, Missing: missing, HasError: kind == "ERROR" || missing})
		return frame{index: index, count: int(count), lastChild: -1}, nil
	}
	root, err := add(0, -1)
	if err != nil {
		return nil, err
	}
	stack = append(stack, root)
	for len(stack) > 0 {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		depth := len(stack) - 1
		f := &stack[depth]
		if f.next >= f.count {
			stack = stack[:depth]
			continue
		}
		if depth+1 >= maxSyntaxDepth {
			return nil, fmt.Errorf("syntax nesting exceeds %d", maxSyntaxDepth)
		}
		if _, err = e.mod.ExportedFunction("ts_node_child").Call(ctx, uint64(scratch)+uint64((depth+1)*32), uint64(scratch)+uint64(depth*32), uint64(f.next)); err != nil {
			return nil, err
		}
		f.next++
		child, addErr := add(depth+1, f.index)
		if addErr != nil {
			return nil, addErr
		}
		if f.lastChild < 0 {
			tree.Nodes[f.index].FirstChild = child.index
		} else {
			tree.Nodes[f.lastChild].NextSibling = child.index
		}
		f.lastChild = child.index
		stack = append(stack, child)
	}
	for i := len(tree.Nodes) - 1; i > 0; i-- {
		if tree.Nodes[i].HasError {
			tree.Nodes[tree.Nodes[i].Parent].HasError = true
		}
	}
	return tree, nil
}

// NodeAt returns the deepest node containing a byte, using half-open spans.
func (t *SyntaxTree) NodeAt(offset int) int {
	if t == nil || len(t.Nodes) == 0 {
		return -1
	}
	found := -1
	for i, n := range t.Nodes {
		if n.StartByte <= offset && offset < n.EndByte {
			found = i
		}
	}
	return found
}
