package memtool

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ctxReader makes long scans cancellable without threading ctx through every
// scan function: once the call (or its yielded job) is cancelled, ReadMemory
// fails immediately and the scan loops check cancelled() to return an error
// instead of a partial result. Returning an error matters for correctness:
// the callers' existing error paths roll back filters and close stores, so a
// cancelled filter cannot replace the session's matches with a truncated set.
type ctxReader struct {
	ProcessReader
	ctx context.Context
}

func (r ctxReader) ReadMemory(address uint64, buf []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.ProcessReader.ReadMemory(address, buf)
}

func (r ctxReader) Err() error { return r.ctx.Err() }

func withCtx(ctx context.Context, r ProcessReader) ProcessReader {
	if r == nil {
		return nil
	}
	return ctxReader{ProcessReader: r, ctx: ctx}
}

// errSessionBusy is returned instead of queueing on the session mutex: a
// yielded scan may still hold it, and queueing would block the agent again.
func errSessionBusy(id string) (*mcp.CallToolResult, MemtoolOutput, error) {
	return errorResult("session %s is busy with a previous operation (likely a yielded job). Wait for it via toolbox operation=job job_action=list, or cancel that job", id)
}

// cancelled reports the cancellation error of a ctxReader; plain readers
// (tests, internal callers) are never cancelled.
func cancelled(r ProcessReader) error {
	if c, ok := r.(interface{ Err() error }); ok {
		if err := c.Err(); err != nil {
			return fmt.Errorf("cancelled: %w", err)
		}
	}
	return nil
}
