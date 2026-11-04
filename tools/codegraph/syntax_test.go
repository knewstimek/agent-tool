package codegraph

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDetachedSyntaxTrees(t *testing.T) {
	for _, tt := range []struct{ lang, source, block string }{
		{"cpp", "// 한글\nvoid f() {\n  call(\"{\", 1);\n}\n", "compound_statement"},
		{"python", "def f():\n    text = \"\"\"fake:\n        x\n\"\"\"\n    call(\n        1)\n", "block"},
	} {
		t.Run(tt.lang, func(t *testing.T) {
			tree, err := ParseSyntaxTree(context.Background(), tt.lang, tt.source)
			if err != nil {
				t.Fatal(err)
			}
			if len(tree.Nodes) < 5 || tree.Nodes[0].HasError {
				t.Fatalf("bad root: %+v", tree)
			}
			call := strings.Index(tt.source, "call")
			at := tree.NodeAt(call)
			found := false
			for i := at; i >= 0; i = tree.Nodes[i].Parent {
				if tree.Nodes[i].Type == tt.block {
					found = true
				}
			}
			if !found {
				t.Fatalf("call lacks enclosing block: %+v", tree.Nodes[at])
			}
			for i, n := range tree.Nodes {
				if n.StartByte < 0 || n.EndByte > len(tt.source) || n.StartByte > n.EndByte {
					t.Fatal("invalid span")
				}
				if i > 0 {
					p := tree.Nodes[n.Parent]
					if n.StartByte < p.StartByte || n.EndByte > p.EndByte {
						t.Fatal("child escaped parent")
					}
				}
				for c := n.FirstChild; c >= 0; c = tree.Nodes[c].NextSibling {
					if tree.Nodes[c].Parent != i {
						t.Fatal("broken child links")
					}
				}
			}
			// Parsing another source must not invalidate the detached snapshot.
			_, err = ParseSyntaxTree(context.Background(), tt.lang, "")
			if err != nil {
				t.Fatal(err)
			}
			if tree.Nodes[at].StartByte != call {
				t.Fatal("snapshot was invalidated")
			}
		})
	}
}

func TestSyntaxCancellationDiscardsEngine(t *testing.T) {
	if _, err := ParseSyntaxTree(context.Background(), "cpp", "void f() {}"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err := ParseSyntaxTree(ctx, "cpp", "void f() {"+strings.Repeat("work();", 200000)+"}")
	if err == nil || ctx.Err() == nil {
		t.Fatalf("expected interrupted parse, got %v", err)
	}
	tree, err := ParseSyntaxTree(context.Background(), "cpp", "void f() { work(); }")
	if err != nil || tree.Nodes[0].HasError {
		t.Fatalf("canceled engine poisoned the pool: %v", err)
	}
}

func TestColdSyntaxEngineHonorsDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	e, err := newEngineContext(ctx, "cpp")
	if e != nil {
		defer e.runtime.Close(context.Background())
	}
	if err == nil || ctx.Err() == nil {
		t.Fatalf("cold initialization ignored deadline: %v", err)
	}
	ctx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := getEngineContext(ctx, "cpp"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled pool acquisition: %v", err)
	}
}

func TestSyntaxErrorsAndBounds(t *testing.T) {
	for _, tt := range []struct{ lang, source string }{
		{"cpp", "void f() { work();"},
		{"python", "def f(:\n  work()\n"},
	} {
		tree, err := ParseSyntaxTree(context.Background(), tt.lang, tt.source)
		if err != nil {
			t.Fatal(err)
		}
		if !tree.Nodes[0].HasError {
			t.Fatalf("invalid syntax reported clean: %+v", tree.Nodes)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ParseSyntaxTree(ctx, "cpp", "void f() {}"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if _, err := ParseSyntaxTree(context.Background(), "go", ""); err == nil {
		t.Fatal("unsupported language accepted")
	}
	if _, err := ParseSyntaxTree(context.Background(), "cpp", string([]byte{255})); err == nil {
		t.Fatal("undecoded bytes accepted")
	}
}
