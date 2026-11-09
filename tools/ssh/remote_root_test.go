package ssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRemoteRootProfileAndImmutableHandle(t *testing.T) {
	profileFile := filepath.Join(t.TempDir(), "connections.json")
	if err := os.WriteFile(profileFile, []byte(`{"connections":{"dev":{"host":"example.invalid","user":"builder","remote_root":"/srv/app"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_TOOL_CONNECTION_PROFILE_FILE", profileFile)
	first := SSHInput{ConnectionProfile: "dev"}
	id, err := ResolveConnection(&first)
	if err != nil {
		t.Fatal(err)
	}
	second := SSHInput{ConnectionID: id}
	if _, err := ResolveConnection(&second); err != nil {
		t.Fatal(err)
	}
	if second.RemoteRoot != "/srv/app" || second.RemoteShell != "posix" {
		t.Fatalf("root not inherited: %+v", second)
	}
	changed := SSHInput{ConnectionID: id, RemoteRoot: "/srv/other"}
	newID, err := ResolveConnection(&changed)
	if err != nil || newID == id {
		t.Fatalf("override must create a distinct handle: %q %v", newID, err)
	}
	original := SSHInput{ConnectionID: id}
	if _, err := ResolveConnection(&original); err != nil || original.RemoteRoot != "/srv/app" {
		t.Fatalf("original handle changed: %+v %v", original, err)
	}
}

func TestRemotePathsAreHostIndependent(t *testing.T) {
	for _, tt := range []struct{ root, input, resolved, display string }{
		{"/srv/app", "a/connection.go", "/srv/app/a/connection.go", "a/connection.go"},
		{"/srv/app", "a/b/connection.go", "/srv/app/a/b/connection.go", "a/b/connection.go"},
		{"/srv/app", "/srv/application/x", "/srv/application/x", "/srv/application/x"},
		{"/srv/app", "../other/x", "/srv/other/x", "/srv/other/x"},
		{"/srv/app", ".", "/srv/app", "."},
		{"/", "etc/config", "/etc/config", "etc/config"},
		{`D:\app`, `a\b.txt`, "D:/app/a/b.txt", "a/b.txt"},
		{"D:/app", "d:/APP/a.txt", "d:/APP/a.txt", "a.txt"},
		{"D:/", "a.txt", "D:/a.txt", "a.txt"},
		{"D:/", ".", "D:/", "."},
		{"D:/", "../a.txt", "D:/a.txt", "a.txt"},
		{"", "relative.txt", "relative.txt", "relative.txt"},
	} {
		in := SSHInput{RemoteRoot: tt.root}
		if err := normalizeRemoteRoot(&in); err != nil {
			t.Fatal(err)
		}
		got := ResolveRemotePath(in.RemoteRoot, tt.input)
		if got != tt.resolved || DisplayRemotePath(in.RemoteRoot, got) != tt.display {
			t.Errorf("root=%q path=%q: resolved=%q display=%q", tt.root, tt.input, got, DisplayRemotePath(in.RemoteRoot, got))
		}
	}
	for _, bad := range []SSHInput{{RemoteRoot: "relative"}, {RemoteRoot: "/srv\napp"}, {RemoteRoot: "C:/bad%PATH%"}, {RemoteRoot: "/srv/app", RemoteShell: "unknown"}} {
		if err := normalizeRemoteRoot(&bad); err == nil {
			t.Errorf("accepted invalid root/shell: %+v", bad)
		}
	}
}

func TestRemoteRootShellQuotingAndScriptPreservation(t *testing.T) {
	in := SSHInput{RemoteRoot: "/srv/app's $data", RemoteShell: "posix", Command: "printf '%s' '/srv/app/unchanged'"}
	command, plan, err := prepareSSHExecution(in)
	if err != nil || plan != nil || command != "cd "+quotePOSIX(in.RemoteRoot)+" && exec sh -c "+quotePOSIX(in.Command) {
		t.Fatalf("unsafe or rewritten command: %s %v", command, err)
	}
	ps := SSHInput{RemoteRoot: "D:/app's files", PowerShellScript: "Write-Output '/absolute/unchanged'"}
	_, plan, err = prepareSSHExecution(ps)
	if err != nil || plan == nil || plan.script != ps.PowerShellScript || plan.remoteRoot != ps.RemoteRoot {
		t.Fatalf("script changed: %+v %v", plan, err)
	}
}

func TestPOSIXRemoteRootExecutionAndFailure(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil && runtime.GOOS == "windows" {
		shell = filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
		_, err = os.Stat(shell)
	}
	if err != nil {
		t.Skip("POSIX shell not installed")
	}
	root := filepath.Join(t.TempDir(), "app's $data")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	root = filepath.ToSlash(root)
	if runtime.GOOS == "windows" {
		root = "/" + strings.ToLower(root[:1]) + root[2:]
	}
	in := SSHInput{RemoteRoot: root, RemoteShell: "posix", Command: "pwd; printf '%s' '/srv/app/unchanged'; exit 17"}
	command, _, err := prepareSSHExecution(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(shell, "-c", command).CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 17 || !strings.Contains(string(out), root) || !strings.Contains(string(out), "/srv/app/unchanged") {
		t.Fatalf("cwd/output/exit lost: err=%v out=%s", err, out)
	}
	in = SSHInput{RemoteRoot: root + "/missing", RemoteShell: "posix", Command: "printf ROOT_BAD; printf SECOND_BAD"}
	command, _, err = prepareSSHExecution(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err = exec.Command(shell, "-c", command).CombinedOutput()
	if err == nil || strings.Contains(string(out), "ROOT_BAD") || strings.Contains(string(out), "SECOND_BAD") {
		t.Fatalf("executed after failed cd: err=%v out=%s", err, out)
	}
	// Closing syntax in user text must never escape the cwd success condition.
	in.Command = "}\nprintf ROOT_BAD"
	command, _, err = prepareSSHExecution(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err = exec.Command(shell, "-c", command).CombinedOutput()
	if err == nil || strings.Contains(string(out), "ROOT_BAD") {
		t.Fatalf("escaped cwd guard: %v %s", err, out)
	}
}
