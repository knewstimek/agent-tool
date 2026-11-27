package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
)

type Credentials struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	Database string `json:"database,omitempty"`
	TLS      *bool  `json:"tls,omitempty"`

	PrivateKey     string `json:"private_key,omitempty"`
	Passphrase     string `json:"passphrase,omitempty"`
	UseAgent       bool   `json:"use_agent,omitempty"`
	HostKeyCheck   string `json:"host_key_check,omitempty"`
	RemoteRoot     string `json:"remote_root,omitempty"`
	RemoteShell    string `json:"remote_shell,omitempty"`
	JumpHost       string `json:"jump_host,omitempty"`
	JumpPort       int    `json:"jump_port,omitempty"`
	JumpUser       string `json:"jump_user,omitempty"`
	JumpPassword   string `json:"jump_password,omitempty"`
	JumpPrivateKey string `json:"jump_private_key,omitempty"`
	JumpPassphrase string `json:"jump_passphrase,omitempty"`

	Token           string `json:"token,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SessionToken    string `json:"session_token,omitempty"`
	Region          string `json:"region,omitempty"`
	Service         string `json:"service,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
}

var awsLabel = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func Decode(kind string, payload []byte) (Credentials, error) {
	var c Credentials
	d := json.NewDecoder(bytes.NewReader(payload))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil || d.Decode(new(any)) != io.EOF {
		return c, fmt.Errorf("invalid credential JSON; check the fields for this profile kind")
	}
	switch kind {
	case SSH, MySQL:
		if strings.TrimSpace(c.Host) == "" || strings.TrimSpace(c.User) == "" || c.Port < 0 || c.Port > 65535 {
			return c, fmt.Errorf("host, user, and a valid optional port are required")
		}
		if kind == SSH {
			if c.Password == "" && c.PrivateKey == "" && !c.UseAgent {
				return c, fmt.Errorf("SSH needs a password, private key, or use_agent")
			}
			if c.HostKeyCheck != "" && c.HostKeyCheck != "strict" && c.HostKeyCheck != "tofu" {
				return c, fmt.Errorf("vault SSH profiles require strict or tofu host key verification")
			}
			if (c.Passphrase != "" && c.PrivateKey == "") || (c.JumpPassphrase != "" && c.JumpPrivateKey == "") {
				return c, fmt.Errorf("a key passphrase requires its private key")
			}
			if c.JumpPort < 0 || c.JumpPort > 65535 {
				return c, fmt.Errorf("invalid jump port")
			}
		}
	case Cloudflare:
		if c.Token == "" || strings.ContainsAny(c.Token, " \t\r\n") {
			return c, fmt.Errorf("Cloudflare needs a valid API token")
		}
	case AWS:
		if c.AccessKeyID == "" || c.SecretAccessKey == "" || !awsLabel.MatchString(c.Service) || !awsLabel.MatchString(c.Region) {
			return c, fmt.Errorf("AWS needs access_key_id, secret_access_key, service, and region")
		}
		u, err := url.Parse(c.Endpoint)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Host != u.Hostname() || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
			(u.Path != "" && u.Path != "/") || !(strings.HasSuffix(u.Host, ".amazonaws.com") || strings.HasSuffix(u.Host, ".amazonaws.com.cn")) {
			return c, fmt.Errorf("AWS endpoint must be an HTTPS origin in amazonaws.com or amazonaws.com.cn")
		}
	default:
		return c, fmt.Errorf("unknown profile kind")
	}
	return c, nil
}
