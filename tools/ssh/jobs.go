package ssh

import (
	"fmt"
	"strings"

	"agent-tool/common"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	gossh "golang.org/x/crypto/ssh"
)

// SSH background jobs live in the shared registry so toolbox operation=job
// lists and waits on them alongside procexec and yielded calls.

const runningPreviewLines = 10

const stagedCancelWarning = "remote completion was not confirmed; the temporary PowerShell script may remain until remote cleanup runs"

func startSSHJob(client *gossh.Client, command string, maxOutputBytes int, outputMode string) (*common.Job, error) {
	return startSSHJobPrepared(client, command, maxOutputBytes, outputMode, nil)
}

func startSSHJobPrepared(client *gossh.Client, command string, maxOutputBytes int, outputMode string, staged *stagedPowerShell) (*common.Job, error) {
	if err := common.CheckJobCapacity(); err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	stdout := common.NewBoundedCaptureMode((maxOutputBytes+1)/2, outputMode)
	stderr := common.NewBoundedCaptureMode(maxOutputBytes/2, outputMode)
	session.Stdout = stdout
	session.Stderr = stderr

	var job *common.Job
	stop := func() {
		if staged != nil {
			job.SetNote(stagedCancelWarning)
		}
		_ = session.Signal(gossh.SIGKILL)
		_ = session.Close()
	}
	job = common.NewJob("ssh", "ssh operation=start", 0, stdout, stderr, stop)
	job.SetRenderer(renderSSHJob)
	common.RegisterJob(job)

	go func() {
		err := session.Run(command)
		exitCode := 0
		completionErr := err
		if exitErr, ok := err.(*gossh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
			completionErr = nil // Non-zero exit still confirms remote completion.
			err = nil           // exit status is carried by exitCode
		}
		if warning := finishStagedPowerShell(client, staged, completionErr); warning != "" || staged != nil {
			job.SetNote(warning)
		}
		_ = session.Close()
		job.Finish(exitCode, err)
	}()
	return job, nil
}

// renderSSHJob keeps the ssh job format for both ssh operation=... and
// toolbox operation=job. A finished job shows its retained output so wait
// returns the result in one call; a running one shows only recent lines.
func renderSSHJob(s common.JobSnapshot, o common.JobRenderOptions) *mcp.CallToolResult {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("job_id: %s\nstatus: %s\nelapsed: %s\n", s.ID, s.Status, s.Elapsed()))
	if !s.Running() {
		sb.WriteString(fmt.Sprintf("exit_code: %d\n", s.ExitCode))
	}
	sb.WriteString(fmt.Sprintf("stdout_bytes: %d\nstderr_bytes: %d\n", s.StdoutBytes, s.StderrBytes))
	if s.StdoutTruncated || s.StderrTruncated {
		sb.WriteString("truncated: true (head and tail retained)\n")
	}
	if s.Note != "" {
		sb.WriteString("cleanup_warning: " + s.Note + "\n")
	}
	if s.Error != "" {
		sb.WriteString("error: " + s.Error + "\n")
	}
	full := !s.Running() && o.Op != "tail" && !o.TailOnly
	// Running status/wait is polled repeatedly, so it shows only a short
	// preview; operation=tail returns the requested tail_lines.
	lines := o.TailLines
	if s.Running() && o.Op != "tail" && lines > runningPreviewLines {
		lines = runningPreviewLines
	}
	for _, stream := range []struct{ name, text string }{{"stdout", s.Stdout}, {"stderr", s.Stderr}} {
		if stream.text == "" {
			continue
		}
		if full {
			sb.WriteString("\n--- " + stream.name + " ---\n" + strings.TrimRight(stream.text, "\n") + "\n")
		} else {
			sb.WriteString("\n--- " + stream.name + " tail ---\n" + common.LastLines(stream.text, lines) + "\n")
		}
	}
	if s.Running() && o.Op != "tail" {
		sb.WriteString(fmt.Sprintf("\n[running; do other work meanwhile. Result: operation=wait job_id=%s]\n", s.ID))
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}},
		IsError: s.Failed(),
	}
}
