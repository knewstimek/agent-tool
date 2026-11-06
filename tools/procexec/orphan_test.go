package procexec

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agent-tool/common"
)

// TestOrphanHelper plays three roles. root starts mid and sleeps; mid starts
// leaf and exits at once, orphaning it; leaf touches a heartbeat file forever.
// taskkill /T walks parent PIDs, so it cannot find leaf once mid is gone.
func TestOrphanHelper(t *testing.T) {
	hb := os.Getenv("AGENT_TOOL_ORPHAN_HB")
	switch os.Getenv("AGENT_TOOL_ORPHAN_ROLE") {
	case "root":
		spawn("mid", hb).Run()
		time.Sleep(60 * time.Second)
	case "mid":
		_ = spawn("leaf", hb).Start()
	case "leaf":
		for {
			_ = os.WriteFile(hb, []byte(time.Now().String()), 0o600)
			time.Sleep(100 * time.Millisecond)
		}
	default:
		return
	}
	os.Exit(0)
}

func spawn(role, hb string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestOrphanHelper$")
	cmd.Env = append(os.Environ(), "AGENT_TOOL_ORPHAN_ROLE="+role, "AGENT_TOOL_ORPHAN_HB="+hb)
	return cmd
}

func modTime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

func TestCancelKillsOrphanedGrandchild(t *testing.T) {
	hb := filepath.Join(t.TempDir(), "heartbeat")
	_, out, _ := execJob(context.Background(), ProcExecInput{
		Command: os.Args[0], Args: []string{"-test.run=^TestOrphanHelper$"},
		Env:            []string{"AGENT_TOOL_ORPHAN_ROLE=root", "AGENT_TOOL_ORPHAN_HB=" + hb},
		MaxOutputChars: common.DefaultOutputChars, OutputView: "raw", TailLines: defaultTailLines,
	}, runOptions{timeout: time.Minute, yieldAfter: 100 * time.Millisecond})
	if out.JobID == "" {
		t.Fatalf("expected a running job: %+v", out)
	}
	deadline := time.Now().Add(10 * time.Second)
	for modTime(hb).IsZero() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if modTime(hb).IsZero() {
		t.Fatal("leaf never started")
	}
	time.Sleep(300 * time.Millisecond) // mid has exited; leaf is now an orphan

	res := common.HandleJobOperation(context.Background(), "cancel", out.JobID, 0, common.JobRenderOptions{})
	if !strings.Contains(text(res), "cancelled") {
		t.Fatalf("cancel failed: %s", text(res))
	}
	time.Sleep(500 * time.Millisecond)
	before := modTime(hb)
	time.Sleep(800 * time.Millisecond)
	if after := modTime(hb); after.After(before) {
		t.Fatalf("orphaned grandchild survived cancel (heartbeat still updating)")
	}
}
