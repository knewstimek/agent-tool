package procexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"agent-tool/common"
	"agent-tool/tools/proclist"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultTimeoutSec = 600
	maxTimeoutSec     = 7200
	defaultYieldSec   = 15
	maxYieldSec       = 300
	defaultTailLines  = 20
	maxTailLines      = 1000
	// waitDelay bounds how long Wait keeps reading pipes after the process
	// exits. A grandchild that inherited stdout (cmd /c start, daemonizing
	// servers) would otherwise keep the job "running" forever.
	waitDelay = 2 * time.Second
	// Logs untouched this long belong to a previous agent-tool run whose
	// registry is gone; a still-running server keeps touching its log.
	staleLogAge = 24 * time.Hour
)

// dangerousEnvKeys are environment variable keys that could be used to hijack execution.
var dangerousEnvKeys = map[string]bool{
	"PATH":                  true,
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"DYLD_LIBRARY_PATH":     true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_FRAMEWORK_PATH":   true,
	"COMSPEC":               true, // Windows command interpreter
	"PATHEXT":               true, // Windows executable extensions
	"IFS":                   true, // shell field separator
}

type ProcExecInput struct {
	Operation      string      `json:"operation,omitempty" jsonschema:"run (default), status, wait, tail, cancel, or list. status/wait/tail/cancel need job_id"`
	Command        string      `json:"command,omitempty" jsonschema:"Command to execute (required for run)"`
	Args           []string    `json:"args,omitempty" jsonschema:"Command arguments"`
	Cwd            string      `json:"cwd,omitempty" jsonschema:"Working directory. Relative paths use workspace/MCP root"`
	Env            []string    `json:"env,omitempty" jsonschema:"Environment variables in KEY=VALUE format. Inherits parent environment by default"`
	TimeoutSec     interface{} `json:"timeout_sec,omitempty" jsonschema:"Hard kill limit for the whole process lifetime in seconds (default 600, max 7200; background default: none). Does not make the call block longer; see yield_after_sec"`
	YieldAfterSec  interface{} `json:"yield_after_sec,omitempty" jsonschema:"Seconds to wait for completion before returning a job_id while the process keeps running (default 15, max 300)"`
	Background     interface{} `json:"background,omitempty" jsonschema:"Return a job_id immediately (output is still captured): true or false. Default: false"`
	Suspended      interface{} `json:"suspended,omitempty" jsonschema:"Start process in suspended state, detached and without output capture. Windows: CREATE_SUSPENDED, Linux: SIGSTOP: true or false. Default: false"`
	JobID          string      `json:"job_id,omitempty" jsonschema:"Job ID returned by a yielded or background run"`
	WaitSec        interface{} `json:"wait_sec,omitempty" jsonschema:"For operation=wait: seconds to block for completion (default 30, max 300)"`
	TailLines      int         `json:"tail_lines,omitempty" jsonschema:"Lines per stream shown for a running job or by operation=tail (default 20, max 1000)"`
	MaxOutputChars int         `json:"max_output_chars,omitempty" jsonschema:"Maximum combined stdout/stderr bytes retained. Default: 32768, Max: 131072. Head and tail are preserved"`
	OutputView     string      `json:"output_view,omitempty" jsonschema:"Command output display: compact (default, folds repeated diagnostics) or raw"`
}

type ProcExecOutput struct {
	PID           int    `json:"pid"`
	JobID         string `json:"job_id,omitempty"`
	ExitCode      int    `json:"exit_code,omitempty"`
	Stdout        string `json:"stdout,omitempty"`
	Stderr        string `json:"stderr,omitempty"`
	Status        string `json:"status"`
	ElapsedMs     int64  `json:"elapsed_ms,omitempty"`
	Truncated     bool   `json:"truncated"`
	StdoutBytes   int64  `json:"stdout_bytes,omitempty"`
	StderrBytes   int64  `json:"stderr_bytes,omitempty"`
	Compacted     bool   `json:"compacted"`
	OmittedLines  int    `json:"omitted_lines,omitempty"`
	CompactGroups int    `json:"compact_groups,omitempty"`
	RawOutputID   string `json:"raw_output_id,omitempty"`
}

// runOptions are the validated knobs for starting a process.
type runOptions struct {
	timeout    time.Duration // 0 = no lifetime limit
	yieldAfter time.Duration // 0 = return immediately (background)
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input ProcExecInput) (*mcp.CallToolResult, ProcExecOutput, error) {
	op := strings.ToLower(strings.TrimSpace(input.Operation))
	if op == "" {
		op = "run"
	}
	outputView, err := common.NormalizeOutputView(input.OutputView)
	if err != nil {
		return errorResult(err.Error())
	}
	input.OutputView = outputView
	if input.TailLines == 0 {
		input.TailLines = defaultTailLines
	}
	if input.TailLines < 1 || input.TailLines > maxTailLines {
		return errorResult(fmt.Sprintf("tail_lines must be between 1 and %d", maxTailLines))
	}

	switch op {
	case "run":
	case "list":
		text := common.FormatJobList(common.ListJobs())
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, ProcExecOutput{Status: "list"}, nil
	case "status", "wait", "tail", "cancel":
		return handleJobOperation(ctx, op, input)
	default:
		return errorResult("operation must be run, status, wait, tail, cancel, or list")
	}

	// 1. Validate command
	if strings.TrimSpace(input.Command) == "" {
		return errorResult("command is required for operation=run (to inspect an existing job, pass operation=status with job_id)")
	}

	suspended := common.FlexBool(input.Suspended)
	background := common.FlexBool(input.Background) || suspended

	// 2. Validate timing
	timeoutSec, ok := common.FlexInt(input.TimeoutSec)
	if !ok || timeoutSec < 0 {
		return errorResult("timeout_sec must be a non-negative integer")
	}
	if timeoutSec > maxTimeoutSec {
		return errorResult(fmt.Sprintf("timeout_sec exceeds maximum (%d). For an unbounded server use background=true without timeout_sec", maxTimeoutSec))
	}
	// Background processes are often servers meant to live with the session,
	// so they get no implicit lifetime limit; an explicit timeout_sec applies.
	if timeoutSec == 0 && !background {
		timeoutSec = defaultTimeoutSec
	}
	yieldSec, ok := common.FlexInt(input.YieldAfterSec)
	if !ok || yieldSec < 0 {
		return errorResult("yield_after_sec must be a non-negative integer")
	}
	if yieldSec == 0 {
		yieldSec = defaultYieldSec
	}
	if yieldSec > maxYieldSec {
		return errorResult(fmt.Sprintf("yield_after_sec exceeds maximum (%d). The process keeps running after yielding; use operation=wait to block again", maxYieldSec))
	}
	opts := runOptions{timeout: time.Duration(timeoutSec) * time.Second, yieldAfter: time.Duration(yieldSec) * time.Second}
	if background {
		opts.yieldAfter = 0
	}

	if input.MaxOutputChars == 0 {
		input.MaxOutputChars = common.DefaultOutputChars
	}
	if input.MaxOutputChars < 1024 || input.MaxOutputChars > common.HardOutputChars {
		return errorResult(fmt.Sprintf("max_output_chars must be between 1024 and %d", common.HardOutputChars))
	}

	// 3. Validate and resolve cwd
	if input.Cwd != "" {
		absPath, err := common.ResolveRequestPath(ctx, req, input.Cwd)
		if err != nil {
			return errorResult(fmt.Sprintf("invalid working directory: %v", err))
		}
		input.Cwd = absPath

		fi, err := os.Stat(input.Cwd)
		if err != nil {
			return errorResult(fmt.Sprintf("working directory not found: %s", input.Cwd))
		}
		if !fi.IsDir() {
			return errorResult(fmt.Sprintf("working directory is not a directory: %s", input.Cwd))
		}
	}

	// 4. Validate env format and block dangerous keys
	for _, e := range input.Env {
		if !strings.Contains(e, "=") {
			return errorResult(fmt.Sprintf("invalid env format (must be KEY=VALUE): %s", e))
		}
		key := strings.ToUpper(e[:strings.Index(e, "=")])
		if dangerousEnvKeys[key] {
			return errorResult(fmt.Sprintf("env key %q is blocked for security (could alter execution behavior)", key))
		}
	}

	if suspended {
		return execSuspended(input)
	}
	return execJob(ctx, input, opts)
}

// execJob starts the process with captured output, then waits up to
// opts.yieldAfter. Fast commands return their full result exactly as a plain
// foreground run would; slow ones are handed to the job registry so the agent
// regains control instead of blocking for minutes.
func execJob(ctx context.Context, input ProcExecInput, opts runOptions) (*mcp.CallToolResult, ProcExecOutput, error) {
	if err := common.CheckJobCapacity(); err != nil {
		return errorResult(err.Error())
	}
	cmd := exec.Command(input.Command, input.Args...)
	if input.Cwd != "" {
		cmd.Dir = input.Cwd
	}
	if len(input.Env) > 0 {
		cmd.Env = mergeEnv(input.Env)
	}
	var stdout, stderr common.OutputSource
	var logs []string
	if opts.yieldAfter == 0 {
		// Background: the child writes straight to files so it survives an
		// agent-tool exit (a pipe would break and kill chatty servers), and
		// the log stays readable after a restart.
		outF, errF, err := createJobLogs()
		if err != nil {
			return errorResult(fmt.Sprintf("failed to create job log files: %v", err))
		}
		defer outF.Close()
		defer errF.Close()
		cmd.Stdout, cmd.Stderr = outF, errF
		stdout = common.NewFileCapture(outF.Name(), (input.MaxOutputChars+1)/2)
		stderr = common.NewFileCapture(errF.Name(), input.MaxOutputChars/2)
		logs = []string{outF.Name(), errF.Name()}
	} else {
		outC := common.NewBoundedCapture((input.MaxOutputChars + 1) / 2)
		errC := common.NewBoundedCapture(input.MaxOutputChars / 2)
		cmd.Stdout, cmd.Stderr = outC, errC
		stdout, stderr = outC, errC
	}
	cmd.WaitDelay = waitDelay
	prepareJobCmd(cmd)

	if err := cmd.Start(); err != nil {
		for _, p := range logs {
			_ = os.Remove(p)
		}
		return errorResult(fmt.Sprintf("failed to execute: %v", err))
	}
	displayCommand, _ := common.TruncateRunes(formatCommand(input.Command, input.Args), 500, "... [command abbreviated]")
	// No KillOnClose: background servers must outlive an agent-tool restart.
	// The job object only makes cancel/timeout reach orphaned grandchildren.
	guard, _ := common.GuardProcess(cmd.Process, common.GuardOptions{})
	job := common.NewJob("procexec", displayCommand, cmd.Process.Pid, stdout, stderr, guard.Kill)
	job.SetLogs(logs...)
	job.SetRenderer(renderForJob)
	go func() {
		err := cmd.Wait()
		guard.Close()
		exitCode := 0
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) || errors.Is(err, exec.ErrWaitDelay) {
			err = nil // exit status is carried by exitCode; lingering pipes are not a failure
		}
		job.Finish(exitCode, err)
	}()
	job.SetLifetime(opts.timeout)

	if opts.yieldAfter == 0 {
		common.RegisterJob(job)
		return renderJob(job.Snapshot(), input.OutputView, input.TailLines, true)
	}

	yield := time.NewTimer(opts.yieldAfter)
	defer yield.Stop()
	select {
	case <-job.Done():
		return renderJob(job.Snapshot(), input.OutputView, input.TailLines, false)
	case <-ctx.Done():
		// The client abandoned the call, so nobody will learn the job_id;
		// keeping the process would leave an untracked orphan.
		_ = job.Cancel()
		job.Wait(context.Background(), 5*time.Second)
		return errorResult(fmt.Sprintf("process canceled: %v", ctx.Err()))
	case <-yield.C:
		common.RegisterJob(job)
		return renderJob(job.Snapshot(), input.OutputView, input.TailLines, true)
	}
}

func handleJobOperation(ctx context.Context, op string, input ProcExecInput) (*mcp.CallToolResult, ProcExecOutput, error) {
	waitSec, ok := common.FlexInt(input.WaitSec)
	if !ok {
		return errorResult("wait_sec must be an integer")
	}
	// Shared with toolbox operation=job, so jobs from any tool can be
	// inspected here too; process jobs keep this tool's format via renderForJob.
	res := common.HandleJobOperation(ctx, op, input.JobID, waitSec,
		common.JobRenderOptions{TailLines: input.TailLines, OutputView: input.OutputView})
	out := ProcExecOutput{}
	if job, found := common.GetJob(input.JobID); found {
		s := job.Snapshot()
		out = ProcExecOutput{PID: s.PID, JobID: s.ID, Status: s.Status, ExitCode: s.ExitCode,
			Stdout: s.Stdout, Stderr: s.Stderr, ElapsedMs: s.Elapsed().Milliseconds()}
	}
	return res, out, nil
}

func renderForJob(s common.JobSnapshot, o common.JobRenderOptions) *mcp.CallToolResult {
	if o.OutputView == "" {
		o.OutputView = "compact"
	}
	if o.Op == "tail" {
		r, _, _ := renderTail(s, o.TailLines)
		return r
	}
	r, _, _ := renderJob(s, o.OutputView, o.TailLines, true)
	return r
}

// renderJob formats a finished job like a classic foreground result, or a
// running one as a short progress report with the next actions spelled out.
// tracked reports whether the job is in the registry (so job_id is usable).
func renderJob(snap common.JobSnapshot, view string, tailLines int, tracked bool) (*mcp.CallToolResult, ProcExecOutput, error) {
	out := ProcExecOutput{
		PID: snap.PID, ExitCode: snap.ExitCode, Status: snap.Status, ElapsedMs: snap.Elapsed().Milliseconds(),
		StdoutBytes: snap.StdoutBytes, StderrBytes: snap.StderrBytes,
		Truncated: snap.StdoutTruncated || snap.StderrTruncated,
	}
	if tracked {
		out.JobID = snap.ID
	}
	var sb strings.Builder
	sb.WriteString("=== Process Execution ===\n")
	sb.WriteString(fmt.Sprintf("  Command: %s\n", snap.Label))
	sb.WriteString(fmt.Sprintf("  PID: %d\n", snap.PID))
	if tracked {
		sb.WriteString(fmt.Sprintf("  Job ID: %s\n", snap.ID))
	}
	if len(snap.Logs) > 0 {
		sb.WriteString(fmt.Sprintf("  Logs: %s (kept 1 hour after exit)\n", strings.Join(snap.Logs, ", ")))
	}

	if snap.Running() {
		sb.WriteString(fmt.Sprintf("  Status: running (elapsed %s)\n", snap.Elapsed()))
		writeTails(&sb, snap, tailLines)
		sb.WriteString(fmt.Sprintf("\n[running; do other work meanwhile. Result: operation=wait job_id=%s | operation=tail | operation=cancel]\n", snap.ID))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, out, nil
	}

	out.Stdout = proclist.SanitizeOutput(snap.Stdout)
	out.Stderr = proclist.SanitizeOutput(snap.Stderr)
	if view == "compact" {
		stdoutCompaction := common.CompactDiagnosticOutput(out.Stdout)
		stderrCompaction := common.CompactDiagnosticOutput(out.Stderr)
		if stdoutCompaction.Compacted || stderrCompaction.Compacted {
			raw := formatRawStreams(out.Stdout, out.Stderr)
			out.RawOutputID = common.PreserveRawOutput("procexec", raw, out.Truncated, snap.StdoutBytes+snap.StderrBytes)
			out.Stdout = stdoutCompaction.Text
			out.Stderr = stderrCompaction.Text
			out.Compacted = true
			out.OmittedLines = stdoutCompaction.OmittedLines + stderrCompaction.OmittedLines
			out.CompactGroups = stdoutCompaction.Groups + stderrCompaction.Groups
		}
	}

	sb.WriteString(fmt.Sprintf("  Exit code: %d\n", snap.ExitCode))
	sb.WriteString(fmt.Sprintf("  Status: %s (elapsed %s)\n", snap.Status, snap.Elapsed()))
	switch snap.Status {
	case common.JobTimedOut:
		sb.WriteString(fmt.Sprintf("  Note: process timed out and was killed (%s). Raise timeout_sec (max %d) if it needs longer; output so far is below\n", snap.Error, maxTimeoutSec))
	case common.JobCancelled:
		sb.WriteString("  Note: cancelled; process tree was killed\n")
	default:
		if snap.Error != "" {
			sb.WriteString(fmt.Sprintf("  Error: %s\n", snap.Error))
		}
	}
	if out.Stdout != "" {
		sb.WriteString(fmt.Sprintf("\n--- stdout ---\n%s", out.Stdout))
		if !strings.HasSuffix(out.Stdout, "\n") {
			sb.WriteString("\n")
		}
	}
	if out.Stderr != "" {
		sb.WriteString(fmt.Sprintf("\n--- stderr ---\n%s", out.Stderr))
		if !strings.HasSuffix(out.Stderr, "\n") {
			sb.WriteString("\n")
		}
	}
	if out.Truncated {
		sb.WriteString(fmt.Sprintf("\n[output truncated: stdout_bytes=%d; stderr_bytes=%d; head and tail shown]\n", out.StdoutBytes, out.StderrBytes))
	}
	if out.Compacted {
		sb.WriteString(fmt.Sprintf("\n[diagnostics compacted: omitted_lines=%d; groups=%d", out.OmittedLines, out.CompactGroups))
		if out.RawOutputID != "" {
			sb.WriteString(fmt.Sprintf("; raw_output_id=%s; retrieve with toolbox operation=output", out.RawOutputID))
		} else {
			sb.WriteString("; raw output preservation unavailable")
		}
		sb.WriteString("]\n")
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
		IsError: snap.Status != common.JobCompleted,
	}, out, nil
}

func renderTail(snap common.JobSnapshot, tailLines int) (*mcp.CallToolResult, ProcExecOutput, error) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("job_id: %s\nstatus: %s\nelapsed: %s\n", snap.ID, snap.Status, snap.Elapsed()))
	if !snap.Running() {
		sb.WriteString(fmt.Sprintf("exit_code: %d\n", snap.ExitCode))
	}
	sb.WriteString(fmt.Sprintf("stdout_bytes: %d\nstderr_bytes: %d\n", snap.StdoutBytes, snap.StderrBytes))
	writeTails(&sb, snap, tailLines)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}},
		ProcExecOutput{PID: snap.PID, JobID: snap.ID, Status: snap.Status, ExitCode: snap.ExitCode,
			ElapsedMs: snap.Elapsed().Milliseconds(), StdoutBytes: snap.StdoutBytes, StderrBytes: snap.StderrBytes}, nil
}

func writeTails(sb *strings.Builder, snap common.JobSnapshot, lines int) {
	if t := common.LastLines(proclist.SanitizeOutput(snap.Stdout), lines); t != "" {
		sb.WriteString(fmt.Sprintf("\n--- stdout (last %d lines) ---\n%s\n", lines, t))
	}
	if t := common.LastLines(proclist.SanitizeOutput(snap.Stderr), lines); t != "" {
		sb.WriteString(fmt.Sprintf("\n--- stderr (last %d lines) ---\n%s\n", lines, t))
	}
}

// createJobLogs makes the stdout/stderr files for a background job and sweeps
// logs left behind by earlier agent-tool runs (the registry that would have
// deleted them did not survive the restart).
func createJobLogs() (*os.File, *os.File, error) {
	// Per-user cache dir, not a fixed name under a shared /tmp: another local
	// user could pre-create that directory and then delete or swap our logs.
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "agent-tool", "jobs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	if entries, err := os.ReadDir(dir); err == nil {
		cutoff := time.Now().Add(-staleLogAge)
		for _, e := range entries {
			if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	outF, err := os.CreateTemp(dir, "job-*.out.log")
	if err != nil {
		return nil, nil, err
	}
	// Same stem as the stdout log so the pair is recognizable in the directory.
	errName := strings.TrimSuffix(outF.Name(), ".out.log") + ".err.log"
	errF, err := os.OpenFile(errName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		outF.Close()
		_ = os.Remove(outF.Name())
		return nil, nil, err
	}
	return outF, errF, nil
}

func execSuspended(input ProcExecInput) (*mcp.CallToolResult, ProcExecOutput, error) {
	pid, err := startSuspended(input.Command, input.Args, input.Cwd, input.Env)
	if err != nil {
		return errorResult(fmt.Sprintf("failed to start suspended: %v", err))
	}

	out := ProcExecOutput{
		PID:    pid,
		Status: "suspended",
	}

	displayCommand, _ := common.TruncateRunes(formatCommand(input.Command, input.Args), 500, "... [command abbreviated]")
	result := fmt.Sprintf("=== Process Execution ===\n  Command: %s\n  PID: %d\n  Status: suspended\n  Use prockill with signal=cont to resume.\n",
		displayCommand, pid)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: result}},
	}, out, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "procexec",
		Description: `Execute a command as a new process. WARNING: runs arbitrary host commands.
Waits up to yield_after_sec (default 15); if still running, returns a job_id and the process continues, so do other work meanwhile. Then operation=wait|status|tail|cancel|list with job_id (cancel kills the process tree).
timeout_sec is the lifetime kill limit (default 600, max 7200), not the blocking time. background=true returns a job_id at once, logs output to files, no implicit limit (servers).
suspended=true starts suspended (resume: prockill signal=cont).
Repeated diagnostics are compacted; output_view=raw disables it; raw_output_id is retrievable via toolbox operation=output for 30 min.`,
	}, Handle)
}

func formatRawStreams(stdout, stderr string) string {
	var sb strings.Builder
	if stdout != "" {
		sb.WriteString("--- stdout ---\n")
		sb.WriteString(stdout)
		if !strings.HasSuffix(stdout, "\n") {
			sb.WriteString("\n")
		}
	}
	if stderr != "" {
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString("--- stderr ---\n")
		sb.WriteString(stderr)
		if !strings.HasSuffix(stderr, "\n") {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// mergeEnv merges user-specified env vars with the current environment.
// User vars override existing ones with the same key.
func mergeEnv(userEnv []string) []string {
	env := os.Environ()
	overrides := make(map[string]string)
	for _, e := range userEnv {
		idx := strings.Index(e, "=")
		if idx > 0 {
			overrides[strings.ToUpper(e[:idx])] = e
		}
	}

	var result []string
	for _, e := range env {
		idx := strings.Index(e, "=")
		if idx > 0 {
			key := strings.ToUpper(e[:idx])
			if _, overridden := overrides[key]; overridden {
				continue // will be added from overrides
			}
		}
		result = append(result, e)
	}
	for _, v := range overrides {
		result = append(result, v)
	}
	return result
}

func formatCommand(cmd string, args []string) string {
	parts := append([]string{cmd}, args...)
	return proclist.SanitizeCommandLine(strings.Join(parts, " "))
}

func errorResult(msg string) (*mcp.CallToolResult, ProcExecOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, ProcExecOutput{}, nil
}
