package bash

import (
	"testing"
)

func TestParseChainOps(t *testing.T) {
	tests := []struct {
		name            string
		cmd             string
		wantSegments    int
		wantChainOps    bool
		wantDelegation  bool
		wantEmpty       bool
		wantSegmentText []string // expected Text for each segment (optional)
	}{
		// Basic chain operators
		{
			name:            "simple &&",
			cmd:             `echo "test1" && echo "test2"`,
			wantSegments:    2,
			wantChainOps:    true,
			wantSegmentText: []string{`echo "test1"`, `echo "test2"`},
		},
		{
			name:            "simple ||",
			cmd:             `echo "hello" || echo "fallback"`,
			wantSegments:    2,
			wantChainOps:    true,
			wantSegmentText: []string{`echo "hello"`, `echo "fallback"`},
		},
		{
			name:         "triple chain",
			cmd:          `cmd1 && cmd2 && cmd3`,
			wantSegments: 3,
			wantChainOps: true,
		},
		{
			name:         "mixed && and ||",
			cmd:          `cmd1 && cmd2 || cmd3`,
			wantSegments: 3,
			wantChainOps: true,
		},

		// No chain ops
		{
			name:         "no operators",
			cmd:          `echo hello`,
			wantSegments: 1,
		},
		{
			name:         "pipe only",
			cmd:          `echo hello | grep h`,
			wantSegments: 1,
		},
		{
			name:         "semicolon only",
			cmd:          `echo a; echo b`,
			wantSegments: 1,
		},
		{
			name:         "empty string",
			cmd:          ``,
			wantSegments: 1,
			wantEmpty:    true, // single segment with empty text
		},

		// Quoted strings — must NOT split
		{
			name:         "&& inside double quotes",
			cmd:          `echo "a && b"`,
			wantSegments: 1,
		},
		{
			name:         "&& inside single quotes",
			cmd:          `echo 'a && b'`,
			wantSegments: 1,
		},
		{
			name:         "|| inside double quotes",
			cmd:          `echo "a || b"`,
			wantSegments: 1,
		},
		{
			name:         "mixed quotes with &&",
			cmd:          `echo "it's && done"`,
			wantSegments: 1,
		},

		// Backslash escaping
		{
			name:         "escaped quote before &&",
			cmd:          `echo \"literal\" && echo done`,
			wantSegments: 2,
			wantChainOps: true,
		},
		{
			name:         "escaped && (backslash before &)",
			cmd:          `echo \&\& echo done`,
			wantSegments: 1, // \& prevents && detection
		},
		{
			name:         "bash single-quote escape pattern",
			cmd:          `echo 'it'\''s' && echo done`,
			wantSegments: 2,
			wantChainOps: true,
		},

		// $() command substitution — depth tracking
		{
			name:            "nested && inside $()",
			cmd:             `echo $(echo "nested" && echo "ops") && echo "top-level"`,
			wantSegments:    2,
			wantChainOps:    true,
			wantDelegation:  true,
			wantSegmentText: []string{`echo $(echo "nested" && echo "ops")`, `echo "top-level"`},
		},
		{
			name:           "$() with && but no top-level chain",
			cmd:            `$(cmd1 && cmd2)`,
			wantSegments:   1,
			wantDelegation: true,
		},
		{
			name:           "$() with no chain inside",
			cmd:            `echo $(echo hello) && echo done`,
			wantSegments:   2,
			wantChainOps:   true,
			wantDelegation: false, // no nested ops
		},
		{
			name:           "deep nesting $($(...))",
			cmd:            `$($(cmd1 && cmd2))`,
			wantSegments:   1,
			wantDelegation: true,
		},
		{
			name:           "result capture with &&",
			cmd:            `result=$(cmd1 && cmd2) && echo $result`,
			wantSegments:   2,
			wantChainOps:   true,
			wantDelegation: true,
		},

		// () subshell — depth tracking
		{
			name:           "subshell grouping",
			cmd:            `(cmd1 && cmd2) || cmd3`,
			wantSegments:   2,
			wantChainOps:   true,
			wantDelegation: true,
		},
		{
			name:         "parens without chain inside",
			cmd:          `(cmd1) && cmd2`,
			wantSegments: 2,
			wantChainOps: true,
			// NeedsDelegation=false — no && inside ()
		},

		// $((expr)) arithmetic
		{
			name:         "arithmetic expansion",
			cmd:          `echo $((1+1)) && echo done`,
			wantSegments: 2,
			wantChainOps: true,
			// NeedsDelegation=false — no chain ops inside $(())
		},

		// Parens inside quotes — must NOT affect depth
		{
			name:            "parens in double quotes",
			cmd:             `echo "(hello)" && echo "done"`,
			wantSegments:    2,
			wantChainOps:    true,
			wantDelegation:  false,
			wantSegmentText: []string{`echo "(hello)"`, `echo "done"`},
		},
		{
			name:         "parens in single quotes",
			cmd:          `echo '(hello)' && echo 'done'`,
			wantSegments: 2,
			wantChainOps: true,
		},

		// Empty segments
		{
			name:         "leading &&",
			cmd:          `&& echo done`,
			wantSegments: 2,
			wantChainOps: true,
			wantEmpty:    true,
		},
		{
			name:         "trailing &&",
			cmd:          `echo test &&`,
			wantSegments: 2,
			wantChainOps: true,
			wantEmpty:    true,
		},

		// Unmatched parens
		{
			name:           "unmatched open paren",
			cmd:            `echo ( && echo done`,
			wantSegments:   1,    // && at depth=1, not split
			wantDelegation: true, // nested ops flagged
		},
		{
			name:         "unmatched close paren",
			cmd:          `echo ) && echo done`,
			wantSegments: 2, // ) doesn't decrement below 0, && at depth=0
			wantChainOps: true,
		},

		// Pipe + chain
		{
			name:         "pipe then &&",
			cmd:          `echo "hello" | grep "h" && echo "found"`,
			wantSegments: 2,
			wantChainOps: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := parseChainOps(tt.cmd)

			if got := len(p.Segments); got != tt.wantSegments {
				t.Errorf("segments count = %d, want %d (segments: %+v)", got, tt.wantSegments, p.Segments)
			}
			if got := p.HasChainOps(); got != tt.wantChainOps {
				t.Errorf("HasChainOps() = %v, want %v", got, tt.wantChainOps)
			}
			if got := p.NeedsDelegation(); got != tt.wantDelegation {
				t.Errorf("NeedsDelegation() = %v, want %v", got, tt.wantDelegation)
			}
			if got := p.HasEmptySegment(); got != tt.wantEmpty {
				t.Errorf("HasEmptySegment() = %v, want %v", got, tt.wantEmpty)
			}

			if tt.wantSegmentText != nil {
				for i, want := range tt.wantSegmentText {
					if i >= len(p.Segments) {
						t.Errorf("segment[%d] missing, want %q", i, want)
						continue
					}
					if got := p.Segments[i].Text; got != want {
						t.Errorf("segment[%d].Text = %q, want %q", i, got, want)
					}
				}
			}
		})
	}
}

func TestHasChainOps(t *testing.T) {
	// Convenience function should match parseChainOps result
	tests := []struct {
		cmd  string
		want bool
	}{
		{`echo a && echo b`, true},
		{`echo a || echo b`, true},
		{`echo "a && b"`, false},
		{`echo 'a || b'`, false},
		{`echo a; echo b`, false},
		{`echo a | grep b`, false},
	}

	for _, tt := range tests {
		if got := hasChainOps(tt.cmd); got != tt.want {
			t.Errorf("hasChainOps(%q) = %v, want %v", tt.cmd, got, tt.want)
		}
	}
}
