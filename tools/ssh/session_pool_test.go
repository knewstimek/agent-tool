package ssh

import (
	"fmt"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	gossh "golang.org/x/crypto/ssh"
)

type auditPoolConn struct {
	gossh.Conn
	closed bool
}

func (c *auditPoolConn) Close() error { c.closed = true; return nil }

func TestPoolDisconnectAndTouchCannotCrossMCPSessions(t *testing.T) {
	owner, other := &mcp.ServerSession{}, &mcp.ServerSession{}
	input := WithConnectionSession(SSHInput{Host: "pool-audit.invalid", User: "builder"}, owner)
	if err := validateInput(&input); err != nil {
		t.Fatal(err)
	}
	foreign := WithConnectionSession(input, other)
	key := sessionKey(input)
	if sessionKey(foreign) == key {
		t.Fatal("pool key omitted the MCP owner")
	}
	conn := &auditPoolConn{}
	before := time.Unix(1, 0)
	pool.mu.Lock()
	pool.sessions[key] = &sessionEntry{client: &gossh.Client{Conn: conn}, owner: owner, lastUsed: before}
	pool.mu.Unlock()
	t.Cleanup(func() { pool.remove(key) })
	if RemoveClientFor(foreign) || conn.closed {
		t.Fatal("foreign disconnect closed an owned connection")
	}
	if RemoveClient(input.Host, input.PortInt, input.User) || conn.closed {
		t.Fatal("legacy disconnect bypassed MCP ownership")
	}
	TouchClientFor(foreign)
	TouchClient(input.Host, input.PortInt, input.User)
	pool.mu.Lock()
	unchanged := pool.sessions[key].lastUsed.Equal(before)
	pool.mu.Unlock()
	if !unchanged {
		t.Fatal("foreign touch changed an owned connection")
	}
	if !RemoveClientFor(input) || !conn.closed {
		t.Fatal("owner could not disconnect")
	}
}

func TestPoolCapacityCannotEvictAnotherMCPSession(t *testing.T) {
	owner, other := &mcp.ServerSession{}, &mcp.ServerSession{}
	p := &sessionPool{sessions: make(map[string]*sessionEntry)}
	var existing []*auditPoolConn
	for i := 0; i < maxSessions; i++ {
		conn := &auditPoolConn{}
		existing = append(existing, conn)
		p.sessions[fmt.Sprint(i)] = &sessionEntry{client: &gossh.Client{Conn: conn}, owner: owner}
	}
	newConn := &auditPoolConn{}
	_, _, err := p.getOrCreate(other, "new", func() (*dialResult, error) {
		return &dialResult{client: &gossh.Client{Conn: newConn}}, nil
	})
	if err == nil || !newConn.closed || len(p.sessions) != maxSessions {
		t.Fatal("capacity rejection did not preserve the bound or close the unused connection")
	}
	for _, conn := range existing {
		if conn.closed {
			t.Fatal("capacity pressure disconnected another MCP session")
		}
	}
	if !p.evictOldestLocked(owner) || len(p.sessions) != maxSessions-1 {
		t.Fatal("owner could not evict its own connection")
	}
}

func TestPoolLateFailureCannotRemoveReplacementClient(t *testing.T) {
	oldConn, replacementConn := &auditPoolConn{}, &auditPoolConn{}
	oldClient, replacement := &gossh.Client{Conn: oldConn}, &gossh.Client{Conn: replacementConn}
	p := &sessionPool{sessions: map[string]*sessionEntry{"reused": {client: replacement}}}
	if p.removeIfClient("reused", oldClient) || replacementConn.closed || p.sessions["reused"].client != replacement {
		t.Fatal("late failure removed the replacement connection")
	}
	if !p.removeIfClient("reused", replacement) || !replacementConn.closed {
		t.Fatal("matching failed client was not removed")
	}
}
