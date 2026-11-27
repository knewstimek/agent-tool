package vault

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

const cliUsage = `agent-tool vault init [--passphrase]
agent-tool vault unlock [--duration 8h]  (only for passphrase vaults)
agent-tool vault list [ssh|mysql|cloudflare|aws]
agent-tool vault import-ssh [--suffix=-vault]
agent-tool vault put KIND NAME [--revision N] [--description TEXT] [--alias NAME] [--tag TAG] [connection flags]
agent-tool vault metadata KIND NAME --revision N [--description TEXT] [--alias NAME] [--tag TAG]
agent-tool vault history KIND NAME
agent-tool vault delete KIND NAME --revision N

Credentials are prompted without echo. To import credential JSON, use --input FILE or --stdin.
By default the vault uses a local key and opens automatically.
Run "agent-tool vault put KIND NAME --help" for connection flags. Only use non-secret text in metadata.
Replacing credentials keeps the profile metadata when no metadata flags are supplied.
The metadata command replaces description, aliases, and tags, leaving credentials intact.`

func RunCLI(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Fprintln(os.Stdout, cliUsage)
		return nil
	}
	path, err := Path()
	if err != nil {
		return err
	}
	switch command := args[0]; command {
	case "init":
		if len(args) == 1 {
			if err := initAutomaticStore(ctx, path); err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "Vault initialized.")
			return nil
		}
		if len(args) != 2 || args[1] != "--passphrase" {
			return fmt.Errorf("usage: agent-tool vault init [--passphrase]")
		}
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("vault already exists")
		}
		password, err := readHidden("New vault passphrase")
		if err != nil {
			return err
		}
		defer clear(password)
		if len(password) < 14 {
			return fmt.Errorf("use a vault passphrase of at least 14 bytes")
		}
		confirm, err := readHidden("Confirm vault passphrase")
		if err != nil {
			return err
		}
		defer clear(confirm)
		if !bytes.Equal(password, confirm) {
			return fmt.Errorf("passphrases do not match")
		}
		if err := initStore(ctx, path, password); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "Vault initialized.")
		return nil
	case "unlock":
		flags := flag.NewFlagSet("vault unlock", flag.ContinueOnError)
		duration := flags.Duration("duration", 8*time.Hour, "Unlock duration, from 1m to 24h")
		if err := flags.Parse(args[1:]); err != nil {
			return flagError(err)
		}
		if flags.NArg() != 0 || *duration < time.Minute || *duration > 24*time.Hour {
			return fmt.Errorf("unlock duration must be between 1m and 24h")
		}
		store, err := open(path, "ro")
		if err != nil {
			return err
		}
		defer store.Close()
		automatic, err := store.automaticKey(ctx)
		if err != nil {
			return err
		}
		if automatic != nil {
			fmt.Fprintln(os.Stdout, "This vault opens automatically.")
			return nil
		}
		key, err := promptUnlock(ctx, store)
		if err != nil {
			return err
		}
		session, cancel := context.WithTimeout(ctx, *duration)
		defer cancel()
		return serve(session, store, key, func() {
			fmt.Fprintf(os.Stdout, "Vault unlocked for up to %s. Press Ctrl+C to lock.\n", *duration)
		})
	case "list":
		kind := ""
		if len(args) == 2 {
			kind = args[1]
		}
		if len(args) > 2 || (kind != "" && !validKind(kind)) {
			return fmt.Errorf("usage: agent-tool vault list [KIND]")
		}
		store, err := open(path, "ro")
		if err != nil {
			return err
		}
		defer store.Close()
		list, err := store.Profiles(ctx, kind, false)
		if err != nil {
			return err
		}
		return printJSON(list)
	case "put", "metadata", "history", "delete":
		if len(args) < 3 || !validKind(args[1]) || !validName(args[2]) {
			return fmt.Errorf("usage: agent-tool vault %s KIND NAME", command)
		}
		profile := Profile{Kind: args[1], Name: args[2]}
		if command == "history" {
			if len(args) != 3 {
				return fmt.Errorf("usage: agent-tool vault history KIND NAME")
			}
			store, err := open(path, "ro")
			if err != nil {
				return err
			}
			defer store.Close()
			history, err := store.history(ctx, profile.Kind, profile.Name)
			if err != nil {
				return err
			}
			return printJSON(history)
		}
		return changeProfile(ctx, path, command, profile, args[3:])
	default:
		return fmt.Errorf("unknown vault command; run agent-tool vault help")
	}
}

type stringsFlag []string

func (s *stringsFlag) Set(value string) error { *s = append(*s, value); return nil }
func (s *stringsFlag) String() string         { return strings.Join(*s, ", ") }

func changeProfile(ctx context.Context, path, operation string, p Profile, args []string) error {
	flags := flag.NewFlagSet("vault "+operation, flag.ContinueOnError)
	expected := flags.Int64("revision", 0, "Expected revision; 0 creates a new profile")
	if operation != "delete" {
		flags.StringVar(&p.Description, "description", "", "Searchable profile description")
		flags.Var((*stringsFlag)(&p.Aliases), "alias", "Searchable alias; repeat for multiple")
		flags.Var((*stringsFlag)(&p.Tags), "tag", "Searchable tag; repeat for multiple")
	}
	var c Credentials
	var importPath, keyPath, jumpKeyPath string
	var fromStdin, promptPassphrase, promptJumpPassphrase, alsoPassword, tls bool
	if operation == "put" {
		flags.StringVar(&importPath, "input", "", "Import credential JSON from an existing file")
		flags.BoolVar(&fromStdin, "stdin", false, "Import credential JSON from standard input")
		switch p.Kind {
		case SSH, MySQL:
			flags.StringVar(&c.Host, "host", "", "Server hostname or IP address")
			flags.IntVar(&c.Port, "port", 0, "Server port")
			flags.StringVar(&c.User, "user", "", "Server username")
		}
		switch p.Kind {
		case SSH:
			flags.StringVar(&keyPath, "key-file", "", "Import private key bytes from an existing file")
			flags.BoolVar(&promptPassphrase, "key-passphrase", false, "Prompt for private key passphrase")
			flags.BoolVar(&alsoPassword, "with-password", false, "Prompt for password even when using a key or agent")
			flags.BoolVar(&c.UseAgent, "use-agent", false, "Use the local SSH agent")
			flags.StringVar(&c.HostKeyCheck, "host-key-check", "tofu", "strict or tofu host key verification")
			flags.StringVar(&c.RemoteRoot, "remote-root", "", "Default remote directory")
			flags.StringVar(&c.RemoteShell, "remote-shell", "", "Default remote shell")
			flags.StringVar(&c.JumpHost, "jump-host", "", "ProxyJump host")
			flags.IntVar(&c.JumpPort, "jump-port", 0, "ProxyJump port")
			flags.StringVar(&c.JumpUser, "jump-user", "", "ProxyJump user")
			flags.StringVar(&jumpKeyPath, "jump-key-file", "", "Import ProxyJump private key bytes")
			flags.BoolVar(&promptJumpPassphrase, "jump-key-passphrase", false, "Prompt for ProxyJump key passphrase")
		case MySQL:
			flags.StringVar(&c.Database, "database", "", "Default database name")
			flags.BoolVar(&tls, "tls", true, "Use verified TLS")
			c.TLS = &tls
		case AWS:
			flags.StringVar(&c.Service, "service", "", "AWS signing service, for example sts")
			flags.StringVar(&c.Region, "region", "", "AWS signing region")
			flags.StringVar(&c.Endpoint, "endpoint", "", "Fixed AWS HTTPS origin")
		}
	}
	if err := flags.Parse(args); err != nil {
		return flagError(err)
	}
	if flags.NArg() != 0 || *expected < 0 || (operation != "put" && *expected == 0) {
		return fmt.Errorf("set --revision to the current revision for edits, replacements, and deletion")
	}
	if fromStdin && importPath != "" {
		return fmt.Errorf("choose either --input or --stdin")
	}
	store, err := open(path, "rw")
	if errors.Is(err, ErrUninitialized) && operation == "put" {
		if err := initAutomaticStore(ctx, path); err != nil {
			return err
		}
		store, err = open(path, "rw")
	}
	if err != nil {
		return err
	}
	defer store.Close()
	key, err := keyForWrite(ctx, store)
	if err != nil {
		return err
	}

	var payload []byte
	if operation == "put" {
		switch {
		case fromStdin:
			payload, err = readBounded(os.Stdin)
		case importPath != "":
			payload, err = readLocalFile(importPath)
		default:
			err = collectCredentials(p.Kind, &c, keyPath, jumpKeyPath, promptPassphrase, promptJumpPassphrase, alsoPassword)
			if err == nil {
				payload, err = json.Marshal(c)
			}
		}
		defer func() { clear(payload) }()
		if err != nil {
			return err
		}
		if _, err := Decode(p.Kind, payload); err != nil {
			return err
		}
	}
	p.Revision, err = store.update(ctx, key, p, *expected, payload, operation)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{"kind": p.Kind, "connection_profile": p.Name, "revision": p.Revision})
}

func collectCredentials(kind string, c *Credentials, keyPath, jumpKeyPath string, keyPassword, jumpPassword, alsoPassword bool) error {
	var err error
	prompt := func(label string, dest *string) {
		if err != nil {
			return
		}
		value, readErr := readHidden(label)
		err = readErr
		*dest = string(value)
		clear(value)
	}
	key := func(path string, dest *string) {
		if err != nil || path == "" {
			return
		}
		data, readErr := readLocalFile(path)
		err = readErr
		*dest = string(data)
		clear(data)
		if *dest == "" && err == nil {
			err = fmt.Errorf("private key file is empty")
		}
	}
	switch kind {
	case SSH:
		key(keyPath, &c.PrivateKey)
		key(jumpKeyPath, &c.JumpPrivateKey)
		if keyPassword {
			prompt("SSH key passphrase", &c.Passphrase)
		}
		if jumpPassword {
			prompt("ProxyJump key passphrase", &c.JumpPassphrase)
		}
		if alsoPassword || (keyPath == "" && !c.UseAgent) {
			prompt("SSH password", &c.Password)
		}
		if c.JumpHost != "" && jumpKeyPath == "" && !c.UseAgent {
			prompt("ProxyJump password (empty to reuse SSH authentication)", &c.JumpPassword)
		}
	case MySQL:
		prompt("MySQL password", &c.Password)
	case Cloudflare:
		prompt("Cloudflare API token", &c.Token)
	case AWS:
		prompt("AWS access key ID", &c.AccessKeyID)
		prompt("AWS secret access key", &c.SecretAccessKey)
		prompt("AWS session token (empty for long-term keys)", &c.SessionToken)
	}
	return err
}

func readBounded(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxPayload+1))
	if err != nil || len(data) > maxPayload {
		clear(data)
		return nil, fmt.Errorf("cannot read credential input or input exceeds 256 KiB")
	}
	return data, nil
}

func readLocalFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open credential input file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("credential input file must be a regular file")
	}
	return readBounded(file)
}

func readHidden(label string) ([]byte, error) {
	terminal, err := openTerminal()
	if err != nil {
		return nil, fmt.Errorf("a local terminal is required for secret input")
	}
	defer terminal.Close()
	fmt.Fprintf(os.Stderr, "%s: ", label)
	value, err := term.ReadPassword(int(terminal.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("could not read secret from local terminal")
	}
	return value, nil
}

func promptUnlock(ctx context.Context, store *Store) (cipher.AEAD, error) {
	password, err := readHidden("Vault passphrase")
	if err != nil {
		return nil, err
	}
	defer clear(password)
	return store.unlock(ctx, password)
}

func keyForWrite(ctx context.Context, store *Store) (cipher.AEAD, error) {
	key, err := store.automaticKey(ctx)
	if err != nil || key != nil {
		return key, err
	}
	return promptUnlock(ctx, store)
}

func flagError(err error) error {
	if err == flag.ErrHelp {
		return nil
	}
	return err
}

func printJSON(value any) error {
	return json.NewEncoder(os.Stdout).Encode(value)
}
