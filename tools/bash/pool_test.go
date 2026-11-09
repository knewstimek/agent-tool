package bash

import (
	"fmt"
	"io"
	"os/exec"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type auditStdin struct{ io.Writer }

func (auditStdin) Close() error { return nil }

func TestPoolCapacityPreservesForeignAndBusyShells(t *testing.T) {
	owner, other := &mcp.ServerSession{}, &mcp.ServerSession{}
	for _, busy := range []bool{false, true} {
		t.Run(fmt.Sprintf("busy=%t", busy), func(t *testing.T) {
			p := &shellPool{sessions: make(map[shellPoolKey]*shellSession)}
			for i := 0; i < maxSessions; i++ {
				entry := &shellSession{cmd: &exec.Cmd{}, stdin: auditStdin{io.Discard}}
				if busy {
					entry.mu.Lock()
					defer entry.mu.Unlock()
				}
				p.sessions[shellPoolKey{owner: owner, name: fmt.Sprint(i)}] = entry
			}
			caller := other
			if busy {
				caller = owner
			}
			if _, _, err := p.getOrCreate(shellPoolKey{owner: caller, name: "new"}, t.TempDir()); err == nil || len(p.sessions) != maxSessions {
				t.Fatal("capacity pressure evicted another owner or exceeded the bound")
			}
		})
	}
}

func TestFailedCommandCannotRemoveReplacementShell(t *testing.T) {
	key := shellPoolKey{name: "reused"}
	old, replacement := &shellSession{}, &shellSession{}
	p := &shellPool{sessions: map[shellPoolKey]*shellSession{key: replacement}}
	if p.remove(key, old) || p.sessions[key] != replacement {
		t.Fatal("a late failure removed the replacement session")
	}
}
