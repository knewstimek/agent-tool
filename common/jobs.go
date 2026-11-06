package common

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Jobs let a tool call return control to the agent while work keeps running.
// MCP calls are synchronous from the client's point of view: while a handler
// blocks, the model can neither answer the user nor do other work, and the
// server has no way to wake the model later. Yielding a job_id and letting the
// agent poll (status/tail/wait) is the only portable way to stay responsive.

const (
	jobRetention    = time.Hour
	MaxRunningJobs  = 32
	maxRetainedJobs = 128 // finished jobs beyond this are evicted oldest-first
	DefaultJobWait  = 30
	MaxJobWait      = 300
)

// Job status values. A job leaves "running" exactly once.
const (
	JobRunning   = "running"
	JobCompleted = "completed"
	JobFailed    = "failed"
	JobCancelled = "cancelled"
	JobTimedOut  = "timed_out"
)

type Job struct {
	mu         sync.Mutex
	id         string
	tool       string
	label      string
	pid        int
	createdAt  time.Time
	finishedAt time.Time
	status     string
	requested  string // terminal status forced by Cancel/Expire; wins over the natural exit
	exitCode   int
	errMsg     string
	stdout     OutputSource
	stderr     OutputSource
	logs       []string // files backing stdout/stderr; removed when the job expires
	stop       func()
	done       chan struct{}
	limit      time.Duration
	result     *mcp.CallToolResult // final result of a yielded tool call
	note       string              // tool-specific caveat shown with the job (e.g. remote cleanup)
	render     JobRenderer
}

// JobRenderOptions carries per-request display choices into a JobRenderer.
type JobRenderOptions struct {
	Op         string // status, wait, tail, or cancel
	TailLines  int
	OutputView string
}

// JobRenderer lets the tool that created a job keep its own result format
// when the job is inspected through the generic toolbox operation=job path.
type JobRenderer func(JobSnapshot, JobRenderOptions) *mcp.CallToolResult

type JobSnapshot struct {
	ID              string
	Tool            string
	Label           string
	PID             int
	Status          string
	ExitCode        int
	Error           string
	CreatedAt       time.Time
	FinishedAt      time.Time
	Stdout          string
	Stderr          string
	StdoutBytes     int64
	StderrBytes     int64
	StdoutTruncated bool
	StderrTruncated bool
	Logs            []string
	Result          *mcp.CallToolResult
	Note            string
}

// OutputSource is a bounded view of a stream (BoundedCapture or FileCapture).
type OutputSource interface {
	Result() (text string, totalBytes int64, truncated bool)
}

var jobRegistry = struct {
	sync.Mutex
	items map[string]*Job
}{items: make(map[string]*Job)}

// NewJob creates an unregistered job. Callers register it only when the work
// outlives the call (RegisterJob), so fast commands never touch the registry.
// stop must terminate the underlying work; it may be called more than once.
func NewJob(tool, label string, pid int, stdout, stderr OutputSource, stop func()) *Job {
	idBytes := make([]byte, 6)
	_, _ = rand.Read(idBytes)
	return &Job{
		id: tool + "-" + hex.EncodeToString(idBytes), tool: tool, label: label, pid: pid,
		createdAt: time.Now(), status: JobRunning, stdout: stdout, stderr: stderr,
		stop: stop, done: make(chan struct{}),
	}
}

// CheckJobCapacity fails fast before starting work that may need a job slot.
func CheckJobCapacity() error {
	jobRegistry.Lock()
	defer jobRegistry.Unlock()
	pruneJobsLocked(time.Now())
	if n := runningJobsLocked(); n >= MaxRunningJobs {
		return fmt.Errorf("%d background jobs are already running (limit %d). List them with operation=list and cancel finished-with work using operation=cancel job_id=<id>", n, MaxRunningJobs)
	}
	return nil
}

func RegisterJob(j *Job) {
	jobRegistry.Lock()
	defer jobRegistry.Unlock()
	pruneJobsLocked(time.Now())
	jobRegistry.items[j.id] = j
	evictFinishedLocked()
}

// SetLogs records files that back the job's output so they are reported to
// the agent and deleted when the job expires.
func (j *Job) SetLogs(paths ...string) {
	j.mu.Lock()
	j.logs = append(j.logs, paths...)
	j.mu.Unlock()
}

func GetJob(id string) (*Job, bool) {
	jobRegistry.Lock()
	defer jobRegistry.Unlock()
	pruneJobsLocked(time.Now())
	j, ok := jobRegistry.items[strings.TrimSpace(id)]
	return j, ok
}

func ListJobs() []JobSnapshot {
	jobRegistry.Lock()
	pruneJobsLocked(time.Now())
	jobs := make([]*Job, 0, len(jobRegistry.items))
	for _, j := range jobRegistry.items {
		jobs = append(jobs, j)
	}
	jobRegistry.Unlock()
	out := make([]JobSnapshot, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, j.Snapshot())
	}
	sort.Slice(out, func(a, b int) bool { return out[a].CreatedAt.Before(out[b].CreatedAt) })
	return out
}

func runningJobsLocked() int {
	n := 0
	for _, j := range jobRegistry.items {
		select {
		case <-j.done:
		default:
			n++
		}
	}
	return n
}

func pruneJobsLocked(now time.Time) {
	for id, j := range jobRegistry.items {
		j.mu.Lock()
		finished := j.finishedAt
		j.mu.Unlock()
		if !finished.IsZero() && now.Sub(finished) > jobRetention {
			dropJobLocked(id, j)
		}
	}
}

func evictFinishedLocked() {
	for len(jobRegistry.items) > maxRetainedJobs {
		var oldestID string
		var oldest time.Time
		for id, j := range jobRegistry.items {
			j.mu.Lock()
			finished := j.finishedAt
			j.mu.Unlock()
			if !finished.IsZero() && (oldestID == "" || finished.Before(oldest)) {
				oldestID, oldest = id, finished
			}
		}
		if oldestID == "" {
			return // only running jobs left; CheckJobCapacity bounds those
		}
		dropJobLocked(oldestID, jobRegistry.items[oldestID])
	}
}

func dropJobLocked(id string, j *Job) {
	delete(jobRegistry.items, id)
	j.mu.Lock()
	logs := j.logs
	j.mu.Unlock()
	for _, p := range logs {
		_ = os.Remove(p)
	}
}

func (j *Job) SetNote(note string) {
	j.mu.Lock()
	j.note = note
	j.mu.Unlock()
}

func (j *Job) SetRenderer(r JobRenderer) {
	j.mu.Lock()
	j.render = r
	j.mu.Unlock()
}

// FinishResult records the final result of a yielded tool call.
func (j *Job) FinishResult(res *mcp.CallToolResult) {
	j.mu.Lock()
	j.result = res
	j.mu.Unlock()
	var err error
	if res != nil && res.IsError {
		err = fmt.Errorf("tool returned an error")
	}
	j.Finish(0, err)
}

func (j *Job) ID() string            { return j.id }
func (j *Job) Done() <-chan struct{} { return j.done }

// SetLifetime arms a hard kill after d measured from job creation. The job is
// reported as timed_out rather than failed so the agent knows to raise the
// limit instead of debugging the command.
func (j *Job) SetLifetime(d time.Duration) {
	if d <= 0 {
		return
	}
	j.mu.Lock()
	j.limit = d
	j.mu.Unlock()
	remaining := time.Until(j.createdAt.Add(d))
	go func() {
		t := time.NewTimer(remaining)
		defer t.Stop()
		select {
		case <-j.done:
		case <-t.C:
			j.terminate(JobTimedOut)
		}
	}()
}

// Finish records the natural outcome. A pending Cancel/timeout overrides it.
func (j *Job) Finish(exitCode int, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	select {
	case <-j.done:
		return
	default:
	}
	j.finishedAt = time.Now()
	j.exitCode = exitCode
	switch {
	case j.requested != "":
		j.status = j.requested
	case err != nil:
		j.status = JobFailed
		j.errMsg = err.Error()
	case exitCode != 0:
		j.status = JobFailed
	default:
		j.status = JobCompleted
	}
	close(j.done)
}

func (j *Job) Cancel() error {
	select {
	case <-j.done:
		return fmt.Errorf("job %s already finished with status %s; nothing to cancel", j.id, j.Snapshot().Status)
	default:
	}
	j.terminate(JobCancelled)
	return nil
}

func (j *Job) terminate(status string) {
	j.mu.Lock()
	if j.requested == "" {
		j.requested = status
	}
	stop := j.stop
	j.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// Wait blocks until the job finishes, d elapses, or ctx is cancelled, and
// reports whether the job is finished.
func (j *Job) Wait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-j.done:
		return true
	case <-t.C:
	case <-ctx.Done():
	}
	select {
	case <-j.done:
		return true
	default:
		return false
	}
}

func (j *Job) Snapshot() JobSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	s := JobSnapshot{
		ID: j.id, Tool: j.tool, Label: j.label, PID: j.pid, Status: j.status,
		ExitCode: j.exitCode, Error: j.errMsg, CreatedAt: j.createdAt, FinishedAt: j.finishedAt,
		Logs: append([]string(nil), j.logs...), Result: j.result, Note: j.note,
	}
	if s.Status == JobTimedOut && s.Error == "" && j.limit > 0 {
		s.Error = fmt.Sprintf("killed after timeout_sec=%d", int(j.limit/time.Second))
	}
	if j.stdout != nil {
		s.Stdout, s.StdoutBytes, s.StdoutTruncated = j.stdout.Result()
	}
	if j.stderr != nil {
		s.Stderr, s.StderrBytes, s.StderrTruncated = j.stderr.Result()
	}
	return s
}

func (s JobSnapshot) Running() bool { return s.Status == JobRunning }

func (s JobSnapshot) Elapsed() time.Duration {
	end := s.FinishedAt
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(s.CreatedAt).Round(100 * time.Millisecond)
}

// LastLines returns the final count lines of s (trailing newlines ignored).
func LastLines(s string, count int) string {
	if count <= 0 || s == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(s, "\r\n"), "\n")
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	return strings.Join(lines, "\n")
}

// FormatJobList renders a compact one-line-per-job table.
func FormatJobList(jobs []JobSnapshot) string {
	if len(jobs) == 0 {
		return "No jobs (finished jobs are kept for 1 hour).\n"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d job(s):\n", len(jobs)))
	for _, s := range jobs {
		label, _ := TruncateRunes(s.Label, 120, "...")
		line := fmt.Sprintf("  %s  %s  elapsed=%s", s.ID, s.Status, s.Elapsed())
		if s.PID > 0 {
			line += fmt.Sprintf("  pid=%d", s.PID)
		}
		if !s.Running() {
			line += fmt.Sprintf("  exit=%d", s.ExitCode)
		}
		sb.WriteString(line + "  " + label + "\n")
	}
	return sb.String()
}
