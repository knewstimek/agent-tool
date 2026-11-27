package ssh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"agent-tool/common"
	"agent-tool/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	connectionHandleTTL  = 30 * time.Minute
	maxConnectionHandles = 64
)

// ConnectionProfile is the non-command portion of an SSH/SFTP request. Local
// profile files may contain secrets and must not be checked into source control.
type ConnectionProfile struct {
	RemoteRoot       string      `json:"remote_root,omitempty"`
	RemoteShell      string      `json:"remote_shell,omitempty"`
	Host             string      `json:"host"`
	Port             interface{} `json:"port,omitempty"`
	User             string      `json:"user"`
	Password         string      `json:"password,omitempty"`
	KeyFile          string      `json:"key_file,omitempty"`
	Passphrase       string      `json:"passphrase,omitempty"`
	UseAgent         interface{} `json:"use_agent,omitempty"`
	HostKeyCheck     string      `json:"host_key_check,omitempty"`
	JumpHost         string      `json:"jump_host,omitempty"`
	JumpPort         interface{} `json:"jump_port,omitempty"`
	JumpUser         string      `json:"jump_user,omitempty"`
	JumpPassword     string      `json:"jump_password,omitempty"`
	JumpKeyFile      string      `json:"jump_key_file,omitempty"`
	JumpPassphrase   string      `json:"jump_passphrase,omitempty"`
	Trusted          bool        `json:"trusted,omitempty"`
	searchMetadata   profileSearchMetadata
	vaultName        string
	vaultFingerprint [sha256.Size]byte
	privateKey       string
	jumpPrivateKey   string
}

// UnmarshalJSON treats local connection profiles as trusted unless they
// explicitly opt out. Profiles are user-maintained local configuration, while
// ad-hoc connection requests remain untrusted.
func (p *ConnectionProfile) UnmarshalJSON(data []byte) error {
	type profileAlias ConnectionProfile
	decoded := profileAlias{Trusted: true}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*p = ConnectionProfile(decoded)
	// These fields were previously ignored. Invalid metadata must not break an existing connection.
	var metadata profileSearchMetadata
	_ = json.Unmarshal(data, &metadata)
	p.searchMetadata = metadata
	return nil
}

type connectionProfileFile struct {
	Connections map[string]ConnectionProfile `json:"connections"`
	Profiles    map[string]ConnectionProfile `json:"profiles"`
}

type connectionHandle struct {
	profile  ConnectionProfile
	lastUsed time.Time
	owner    *mcp.ServerSession
}

var connectionHandles = struct {
	sync.Mutex
	items map[string]connectionHandle
}{items: make(map[string]connectionHandle)}

// ResolveConnection fills omitted connection fields from a local profile or
// an opaque handle in the nil-session namespace. Explicit request fields override
// local profile defaults. The returned handle can be reused by SSH and SFTP.
func ResolveConnection(input *SSHInput) (string, error) {
	return resolveConnection(context.Background(), nil, input, nil)
}

// Only the hash is retained as a private scope key; credentials are never emitted.
func ConnectionAliasScope(input SSHInput) string {
	profile := profileFromInput(input)
	// Canonicalize exactly the defaults applied before connecting. This must
	// remain stable both before and after validation, including ProxyJump.
	canonical := input
	if err := validateInput(&canonical); err == nil {
		profile = profileFromInput(canonical)
		profile.Port = canonical.PortInt
		profile.UseAgent = common.FlexBool(canonical.UseAgent) || canonical.KeyFile == "" && canonical.privateKey == "" && canonical.Password == ""
		if canonical.JumpHost != "" {
			profile.JumpPort = canonical.JumpPortInt
		}
	}
	profile.RemoteRoot, profile.RemoteShell, profile.Trusted = "", "", false
	data, _ := json.Marshal(profile)
	if profile.vaultName != "" {
		data = fmt.Appendf(data, "\x00%q\x00%q\x00%q", profile.vaultName, profile.privateKey, profile.jumpPrivateKey)
	}
	return fmt.Sprintf("remote:%x", sha256.Sum256(data))
}

// Management resolves identity without depending on a possibly unregistered
// remote_root alias, and does not allocate connection handles or connect.
func ResolveDirectoryAliasScope(profileName, handleID string) (string, error) {
	return resolveDirectoryAliasScope(context.Background(), nil, profileName, handleID)
}

func ResolveDirectoryAliasScopeForRequest(ctx context.Context, req *mcp.CallToolRequest, profileName, handleID string) (string, error) {
	ctx = common.WithToolRequest(ctx, req)
	return resolveDirectoryAliasScope(ctx, common.ToolSession(ctx), profileName, handleID)
}

func resolveDirectoryAliasScope(ctx context.Context, owner *mcp.ServerSession, profileName, handleID string) (string, error) {
	profileName, handleID = strings.TrimSpace(profileName), strings.TrimSpace(handleID)
	if profileName != "" && handleID != "" {
		return "", fmt.Errorf("use either connection_profile or connection_id, not both")
	}
	var profile ConnectionProfile
	var err error
	if handleID != "" {
		profile, err = loadConnectionHandle(ctx, owner, handleID)
	} else if profileName != "" {
		profile, err = loadConnectionProfile(ctx, profileName)
	} else {
		return "", fmt.Errorf("remote connection reference required")
	}
	if err != nil {
		return "", err
	}
	input := SSHInput{}
	applyProfileDefaults(&input, profile)
	return ConnectionAliasScope(input), nil
}

func ResolveConnectionForRequest(ctx context.Context, req *mcp.CallToolRequest, input *SSHInput) (string, error) {
	ctx = common.WithToolRequest(ctx, req)
	if input != nil {
		input.requestSession = common.ToolSession(ctx)
	}
	return resolveConnection(ctx, common.ToolSession(ctx), input, func(root string) (string, error) {
		if !strings.HasPrefix(root, "@") {
			return root, nil
		}
		return common.ExpandDirectoryAlias(common.DirectoryAliasMap(ctx, req, ConnectionAliasScope(*input)), root, ResolveRemotePath)
	})
}

// WithConnectionSession preserves the MCP owner when SFTP reconstructs input
// for asynchronous pool access. It is never accepted as a JSON argument.
func WithConnectionSession(input SSHInput, owner *mcp.ServerSession) SSHInput {
	input.requestSession = owner
	return input
}

func resolveConnection(ctx context.Context, owner *mcp.ServerSession, input *SSHInput, expandRoot func(string) (string, error)) (string, error) {
	if input == nil {
		return "", fmt.Errorf("connection input is required")
	}
	profileName := strings.TrimSpace(input.ConnectionProfile)
	handleID := strings.TrimSpace(input.ConnectionID)
	if profileName != "" && handleID != "" {
		return "", fmt.Errorf("use either connection_profile or connection_id, not both")
	}
	hasOverrides := hasExplicitConnectionFields(*input)
	if handleID != "" && hasOverrides {
		return "", fmt.Errorf("connection_id cannot be combined with host/user/auth/jump overrides")
	}

	var base ConnectionProfile
	var err error
	if handleID != "" {
		base, err = loadConnectionHandle(ctx, owner, handleID)
		if err != nil {
			return "", err
		}
	} else if profileName != "" {
		base, err = loadConnectionProfile(ctx, profileName)
		if err != nil {
			return "", err
		}
	}
	if base.vaultName != "" && hasOverrides {
		return "", fmt.Errorf("vault SSH profiles cannot be combined with host, authentication, or jump overrides")
	}
	if profileName != "" && hasOverrides {
		// Redirecting a trusted profile must not inherit warning suppression.
		base.Trusted = false
	}
	applyProfileDefaults(input, base)
	if expandRoot != nil {
		input.RemoteRoot, err = expandRoot(input.RemoteRoot)
		if err != nil {
			return "", err
		}
	}
	if err := normalizeRemoteRoot(input); err != nil {
		return "", err
	}
	if base.Trusted {
		input.TrustedProfile = true
	}

	if handleID == "" || input.RemoteRoot != base.RemoteRoot || input.RemoteShell != base.RemoteShell {
		handleID, err = rememberConnection(owner, *input)
		if err != nil {
			return "", err
		}
	}
	input.ResolvedConnectionID = handleID
	return handleID, nil
}

func loadConnectionProfile(ctx context.Context, name string) (ConnectionProfile, error) {
	profile, err := loadVaultConnectionProfile(ctx, name)
	if errors.Is(err, vault.ErrNotFound) || errors.Is(err, vault.ErrUninitialized) {
		return loadLocalConnectionProfile(name)
	}
	return profile, err
}

func loadVaultConnectionProfile(ctx context.Context, name string) (ConnectionProfile, error) {
	c, err := vault.Resolve(ctx, vault.SSH, name)
	if err != nil {
		return ConnectionProfile{}, err
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return ConnectionProfile{}, err
	}
	defer clear(encoded)
	return ConnectionProfile{
		Host: c.Host, Port: c.Port, User: c.User, Password: c.Password,
		Passphrase: c.Passphrase, UseAgent: c.UseAgent, HostKeyCheck: c.HostKeyCheck,
		RemoteRoot: c.RemoteRoot, RemoteShell: c.RemoteShell,
		JumpHost: c.JumpHost, JumpPort: c.JumpPort, JumpUser: c.JumpUser, JumpPassword: c.JumpPassword, JumpPassphrase: c.JumpPassphrase,
		vaultName: name, vaultFingerprint: sha256.Sum256(encoded), privateKey: c.PrivateKey, jumpPrivateKey: c.JumpPrivateKey,
	}, nil
}

func hasExplicitConnectionFields(input SSHInput) bool {
	return input.Host != "" || input.Port != nil || input.User != "" || input.Password != "" ||
		input.KeyFile != "" || input.Passphrase != "" || input.UseAgent != nil || input.HostKeyCheck != "" ||
		input.JumpHost != "" || input.JumpPort != nil || input.JumpUser != "" || input.JumpPassword != "" ||
		input.JumpKeyFile != "" || input.JumpPassphrase != ""
}

func loadLocalConnectionProfile(name string) (ConnectionProfile, error) {
	profiles, path, err := readLocalConnectionProfiles()
	if err != nil {
		return ConnectionProfile{}, err
	}
	profile, ok := profiles[name]
	if !ok {
		return ConnectionProfile{}, fmt.Errorf("connection_profile %q not found in %s", name, path)
	}
	return profile, nil
}

func readLocalConnectionProfiles() (map[string]ConnectionProfile, string, error) {
	path := strings.TrimSpace(os.Getenv("AGENT_TOOL_CONNECTION_PROFILE_FILE"))
	if path == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return nil, "", fmt.Errorf("cannot locate local connection profile directory: %w", err)
		}
		path = filepath.Join(configDir, "agent-tool", "connections.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, path, fmt.Errorf("cannot read local connection profiles %s: %w", path, err)
	}
	var file connectionProfileFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, path, fmt.Errorf("invalid local connection profile file %s: %w", path, err)
	}
	profiles := file.Connections
	if len(profiles) == 0 {
		profiles = file.Profiles
	}
	return profiles, path, nil
}

func rememberConnection(owner *mcp.ServerSession, input SSHInput) (string, error) {
	profile := profileFromInput(input)
	if profile.vaultName != "" {
		profile = ConnectionProfile{
			vaultName: profile.vaultName, vaultFingerprint: profile.vaultFingerprint,
			RemoteRoot: profile.RemoteRoot, RemoteShell: profile.RemoteShell,
		}
	}
	now := time.Now()
	connectionHandles.Lock()
	defer connectionHandles.Unlock()
	pruneConnectionHandlesLocked(now)
	for id, entry := range connectionHandles.items {
		if entry.owner == owner && reflect.DeepEqual(entry.profile, profile) {
			entry.lastUsed = now
			connectionHandles.items[id] = entry
			return id, nil
		}
	}

	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("cannot create connection_id: %w", err)
	}
	id := "conn_" + hex.EncodeToString(random[:])
	if len(connectionHandles.items) >= maxConnectionHandles {
		var oldestID string
		var oldest time.Time
		for candidate, entry := range connectionHandles.items {
			if oldestID == "" || entry.lastUsed.Before(oldest) {
				oldestID, oldest = candidate, entry.lastUsed
			}
		}
		delete(connectionHandles.items, oldestID)
	}
	connectionHandles.items[id] = connectionHandle{profile: profile, lastUsed: now, owner: owner}
	return id, nil
}

func loadConnectionHandle(ctx context.Context, owner *mcp.ServerSession, id string) (ConnectionProfile, error) {
	connectionHandles.Lock()
	now := time.Now()
	pruneConnectionHandlesLocked(now)
	entry, ok := connectionHandles.items[id]
	if !ok || entry.owner != owner {
		connectionHandles.Unlock()
		return ConnectionProfile{}, fmt.Errorf("connection_id %q not found or expired", id)
	}
	entry.lastUsed = now
	connectionHandles.items[id] = entry
	connectionHandles.Unlock()
	if entry.profile.vaultName == "" {
		return entry.profile, nil
	}
	profile, err := loadVaultConnectionProfile(ctx, entry.profile.vaultName)
	if err != nil {
		return ConnectionProfile{}, err
	}
	if profile.vaultFingerprint != entry.profile.vaultFingerprint {
		connectionHandles.Lock()
		delete(connectionHandles.items, id)
		connectionHandles.Unlock()
		return ConnectionProfile{}, fmt.Errorf("connection profile changed; call again with connection_profile to obtain a new connection_id")
	}
	profile.RemoteRoot, profile.RemoteShell = entry.profile.RemoteRoot, entry.profile.RemoteShell
	return profile, nil
}

func pruneConnectionHandlesLocked(now time.Time) {
	for id, entry := range connectionHandles.items {
		if now.Sub(entry.lastUsed) > connectionHandleTTL {
			delete(connectionHandles.items, id)
		}
	}
}

func profileFromInput(input SSHInput) ConnectionProfile {
	return ConnectionProfile{
		RemoteRoot: input.RemoteRoot, RemoteShell: input.RemoteShell,
		Host: input.Host, Port: input.Port, User: input.User, Password: input.Password,
		KeyFile: input.KeyFile, Passphrase: input.Passphrase, UseAgent: input.UseAgent,
		HostKeyCheck: input.HostKeyCheck, JumpHost: input.JumpHost, JumpPort: input.JumpPort,
		JumpUser: input.JumpUser, JumpPassword: input.JumpPassword,
		JumpKeyFile: input.JumpKeyFile, JumpPassphrase: input.JumpPassphrase,
		Trusted:   input.TrustedProfile,
		vaultName: input.vaultName, vaultFingerprint: input.vaultFingerprint, privateKey: input.privateKey, jumpPrivateKey: input.jumpPrivateKey,
	}
}

func applyProfileDefaults(input *SSHInput, profile ConnectionProfile) {
	input.vaultName, input.privateKey, input.jumpPrivateKey = profile.vaultName, profile.privateKey, profile.jumpPrivateKey
	input.vaultFingerprint = profile.vaultFingerprint
	if input.RemoteRoot == "" {
		input.RemoteRoot = profile.RemoteRoot
	}
	if input.RemoteShell == "" {
		input.RemoteShell = profile.RemoteShell
	}
	if input.Host == "" {
		input.Host = profile.Host
	}
	if input.Port == nil {
		input.Port = profile.Port
	}
	if input.User == "" {
		input.User = profile.User
	}
	if input.Password == "" {
		input.Password = profile.Password
	}
	if input.KeyFile == "" {
		input.KeyFile = profile.KeyFile
	}
	if input.Passphrase == "" {
		input.Passphrase = profile.Passphrase
	}
	if input.UseAgent == nil {
		input.UseAgent = profile.UseAgent
	}
	if input.HostKeyCheck == "" {
		input.HostKeyCheck = profile.HostKeyCheck
	}
	if input.JumpHost == "" {
		input.JumpHost = profile.JumpHost
	}
	if input.JumpPort == nil {
		input.JumpPort = profile.JumpPort
	}
	if input.JumpUser == "" {
		input.JumpUser = profile.JumpUser
	}
	if input.JumpPassword == "" {
		input.JumpPassword = profile.JumpPassword
	}
	if input.JumpKeyFile == "" {
		input.JumpKeyFile = profile.JumpKeyFile
	}
	if input.JumpPassphrase == "" {
		input.JumpPassphrase = profile.JumpPassphrase
	}
}
