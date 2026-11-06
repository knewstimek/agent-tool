package common

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// YieldAfter is how long a yielding tool call may block before it returns a
// job_id. A var so tests can shorten it.
var YieldAfter = 15 * time.Second

// runYielding runs work and returns its result if it finishes within
// YieldAfter. Otherwise the call returns a job_id and work keeps running on a
// context detached from the request, cancellable only through the job.
func runYielding(ctx context.Context, tool, label string, work func(context.Context) *mcp.CallToolResult) *mcp.CallToolResult {
	// WithoutCancel: the request context ends when we return the job_id, but
	// the work must outlive it. Values (session, roots) are still carried.
	workCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	job := NewJob(tool, label, 0, nil, nil, cancel)
	go func() {
		defer cancel()
		defer func() {
			// rawHandler's recover runs on the caller goroutine, not this one.
			if r := recover(); r != nil {
				log.Printf("PANIC in tool %q: %v\n%s", tool, r, debug.Stack())
				job.FinishResult(toolError(fmt.Sprintf("internal error: panic in %s (see server logs)", tool)))
			}
		}()
		res := work(workCtx)
		if res == nil {
			res = toolError(fmt.Sprintf("%s returned no result", tool))
		}
		LimitToolResultText(res, HardOutputChars)
		job.FinishResult(res)
	}()

	timer := time.NewTimer(YieldAfter)
	defer timer.Stop()
	select {
	case <-job.Done():
		return job.Snapshot().Result
	case <-ctx.Done():
		// Nobody will learn a job_id for an abandoned call; stop the work.
		cancel()
		return toolError(fmt.Sprintf("%s canceled: %v", tool, ctx.Err()))
	case <-timer.C:
		if err := CheckJobCapacity(); err != nil {
			// No slot: fall back to the old blocking behavior rather than
			// failing work that is already half done.
			select {
			case <-job.Done():
				return job.Snapshot().Result
			case <-ctx.Done():
				cancel()
				return toolError(fmt.Sprintf("%s canceled: %v", tool, ctx.Err()))
			}
		}
		RegisterJob(job)
		return renderJobDefault(job.Snapshot(), JobRenderOptions{Op: "status"})
	}
}

// HandleJobOperation implements status/wait/tail/cancel/list for any job.
// Cancelling the request context only ends a wait; the job keeps running.
func HandleJobOperation(ctx context.Context, op, id string, waitSec int, opts JobRenderOptions) *mcp.CallToolResult {
	op = strings.ToLower(strings.TrimSpace(op))
	if op == "" {
		op = "status"
	}
	if op == "list" {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: FormatJobList(ListJobs())}}}
	}
	if op != "status" && op != "wait" && op != "tail" && op != "cancel" {
		return toolError("job_action must be status, wait, tail, cancel, or list")
	}
	if strings.TrimSpace(id) == "" {
		return toolError(fmt.Sprintf("job_id is required for %s. List known jobs with toolbox operation=job job_action=list", op))
	}
	job, ok := GetJob(id)
	if !ok {
		return toolError(fmt.Sprintf("job %q not found: finished jobs expire after 1 hour and jobs do not survive an agent-tool restart. List known jobs with toolbox operation=job job_action=list", strings.TrimSpace(id)))
	}
	switch op {
	case "cancel":
		if err := job.Cancel(); err != nil {
			return toolError(err.Error())
		}
		job.Wait(ctx, 5*time.Second)
	case "wait":
		if waitSec < 0 {
			return toolError("wait_sec must be non-negative")
		}
		if waitSec == 0 {
			waitSec = DefaultJobWait
		}
		if waitSec > MaxJobWait {
			return toolError(fmt.Sprintf("wait_sec exceeds maximum (%d); call wait again if the job is still running", MaxJobWait))
		}
		job.Wait(ctx, time.Duration(waitSec)*time.Second)
	}
	opts.Op = op
	if opts.TailLines <= 0 {
		opts.TailLines = 20
	}
	job.mu.Lock()
	render := job.render
	job.mu.Unlock()
	if render == nil {
		render = renderJobDefault
	}
	return render(job.Snapshot(), opts)
}

// renderJobDefault shows a yielded tool call: a progress note while running,
// then the tool's own final result prefixed by one job line.
func renderJobDefault(s JobSnapshot, _ JobRenderOptions) *mcp.CallToolResult {
	if s.Running() {
		// Kept short: agents poll, so this text is paid for on every check.
		// "do other work" stops agents from blocking on wait right away.
		text := fmt.Sprintf("%s still running: job_id=%s (%s). Do other work meanwhile; result: toolbox operation=job job_action=wait job_id=%s (or job_action=cancel)\n",
			s.Tool, s.ID, s.Elapsed(), s.ID)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
	}
	header := fmt.Sprintf("[job %s: %s %s after %s]\n", s.ID, s.Tool, s.Status, s.Elapsed())
	if s.Status == JobCancelled {
		header += "[result below is what the tool returned when it stopped]\n"
	}
	out := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: header}}, IsError: s.Status != JobCompleted}
	if s.Result != nil {
		out.Content = append(out.Content, s.Result.Content...)
	}
	return out
}
