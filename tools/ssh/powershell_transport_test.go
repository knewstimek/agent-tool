package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

type scriptSSHFixture struct {
	client   *gossh.Client
	files    *sftp.Client
	mu       sync.Mutex
	commands []string
	hold     bool
	exit     uint32
}

func newScriptSSHFixture(t *testing.T, exit uint32, hold bool) *scriptSSHFixture {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &gossh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &scriptSSHFixture{exit: exit, hold: hold}
	handlers := sftp.InMemHandler()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		server, channels, requests, err := gossh.NewServerConn(conn, config)
		if err != nil {
			conn.Close()
			return
		}
		defer server.Close()
		go gossh.DiscardRequests(requests)
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				continue
			}
			go func() {
				defer channel.Close()
				for request := range requests {
					switch request.Type {
					case "subsystem":
						_ = request.Reply(true, nil)
						server := sftp.NewRequestServer(channel, handlers)
						_ = server.Serve()
						_ = server.Close()
						return
					case "exec":
						var payload struct{ Command string }
						_ = gossh.Unmarshal(request.Payload, &payload)
						f.mu.Lock()
						f.commands = append(f.commands, payload.Command)
						f.mu.Unlock()
						_ = request.Reply(true, nil)
						tokens := strings.Fields(payload.Command)
						probe := tokens[len(tokens)-1] == encodePowerShell("[Console]::Out.Write([IO.Path]::GetTempPath())")
						if probe {
							_, _ = io.WriteString(channel, "C:\\agent tool's temp\\")
							_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{0}))
							return
						}
						data, _ := base64.StdEncoding.DecodeString(tokens[len(tokens)-1])
						units := make([]uint16, len(data)/2)
						for i := range units {
							units[i] = uint16(data[2*i]) | uint16(data[2*i+1])<<8
						}
						script := string(utf16.Decode(units))
						var code uint32
						if strings.Contains(script, "[IO.File]::Open") {
							encoded, _ := io.ReadAll(channel)
							content, err := base64.StdEncoding.DecodeString(string(encoded))
							match := regexp.MustCompile(`\[IO.File\]::Open\('((?:[^']|'')*)'`).FindStringSubmatch(script)
							if err != nil || len(match) != 2 {
								code = 1
							} else {
								file, err := f.files.OpenFile(strings.ReplaceAll(match[1], "''", "'"), os.O_WRONLY|os.O_CREATE|os.O_EXCL)
								if err != nil {
									code = 1
								} else {
									_, err = file.Write(content)
									file.Close()
									if err != nil {
										code = 1
									}
								}
							}
						} else if strings.Contains(script, "Test-Path -LiteralPath") {
							match := regexp.MustCompile(`Test-Path -LiteralPath '((?:[^']|'')*)'`).FindStringSubmatch(script)
							if len(match) != 2 {
								code = 1
							} else {
								err := f.files.Remove(strings.ReplaceAll(match[1], "''", "'"))
								if err != nil && !os.IsNotExist(err) {
									code = 1
								}
							}
						} else {
							code = f.exit
						}
						if strings.Contains(script, "[IO.File]::Open") || strings.Contains(script, "Test-Path -LiteralPath") {
							_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{code}))
							return
						}
						// Hold completion to simulate cancellation without confirmed
						// remote termination. Signal requests still receive a reply.
						if f.hold {
							for request := range requests {
								_ = request.Reply(true, nil)
							}
							return
						}
						_, _ = io.WriteString(channel, "script output")
						_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{f.exit}))
						return
					default:
						_ = request.Reply(false, nil)
					}
				}
			}()
		}
	}()
	client, err := gossh.Dial("tcp", listener.Addr().String(), &gossh.ClientConfig{
		User: "test", HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second,
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	f.client = client
	files, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		listener.Close()
		t.Fatal(err)
	}
	f.files = files
	if err := files.MkdirAll("/C:/agent tool's temp"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { files.Close(); client.Close(); listener.Close() })
	return f
}

func TestPowerShellStagingTransportAndCleanup(t *testing.T) {
	for _, exit := range []uint32{0, 29} {
		f := newScriptSSHFixture(t, exit, false)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		plan, err := planPowerShell(SSHInput{PowerShellScript: "Write-Output '한글 😀'; exit 29"})
		if err != nil {
			t.Fatal(err)
		}
		staged, err := stagePowerShell(ctx, f.client, plan)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		file, err := f.files.Open(staged.remotePath)
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(file)
		file.Close()
		if err != nil || string(content) != "\ufeff"+plan.script {
			t.Fatalf("script bytes changed: %v", err)
		}
		if len(staged.command) >= powerShellInlineLimit || strings.Contains(staged.command, plan.script) {
			t.Fatal("script body leaked into command line")
		}
		result, err := executeCommand(ctx, f.client, staged.command, 4096, "head_tail")
		cancel()
		if err != nil || result.ExitCode != int(exit) {
			t.Fatalf("exit status lost: result=%v err=%v", result, err)
		}
		if warning := finishStagedPowerShell(f.client, staged, err); warning != "" {
			t.Fatal(warning)
		}
		if _, err := f.files.Stat(staged.remotePath); !os.IsNotExist(err) {
			t.Fatalf("staged script was not deleted: %v", err)
		}
	}
}

func TestPowerShellBackgroundCleanupAndCancel(t *testing.T) {
	for _, hold := range []bool{false, true} {
		f := newScriptSSHFixture(t, 0, hold)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		plan, _ := planPowerShell(SSHInput{PowerShellScript: "Write-Output 'test'"})
		staged, err := stagePowerShell(ctx, f.client, plan)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		job, err := startSSHJobPrepared(f.client, staged.command, 4096, "head_tail", staged)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			sshJobs.Lock()
			delete(sshJobs.items, job.id)
			sshJobs.Unlock()
		})
		if hold {
			// Wait until the exec request is active before cancelling.
			deadline := time.Now().Add(3 * time.Second)
			for {
				f.mu.Lock()
				started := len(f.commands) >= 3
				f.mu.Unlock()
				if started {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("job did not start")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if err := job.cancel(); err != nil {
				t.Fatal(err)
			}
		}
		deadline := time.Now().Add(3 * time.Second)
		var snap sshJobSnapshot
		for {
			snap = job.snapshot()
			if !snap.FinishedAt.IsZero() {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("job did not finish")
			}
			time.Sleep(5 * time.Millisecond)
		}
		_, statErr := f.files.Stat(staged.remotePath)
		if hold {
			if snap.Status != "cancelled" || snap.CleanupWarning == "" || statErr != nil {
				t.Fatalf("cancel must report unconfirmed completion and retain file: %+v stat=%v", snap, statErr)
			}
		} else if snap.Status != "completed" || snap.CleanupWarning != "" || !os.IsNotExist(statErr) {
			t.Fatalf("background completion did not clean up: %+v stat=%v", snap, statErr)
		}
	}
}
