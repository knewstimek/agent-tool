package httpreq

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"agent-tool/internal/vault"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func authorizeProfile(ctx context.Context, req *http.Request, input HTTPReqInput) (func(string) string, error) {
	kind := strings.ToLower(strings.TrimSpace(input.ProfileKind))
	if kind != vault.Cloudflare && kind != vault.AWS {
		return nil, fmt.Errorf("profile_kind must be cloudflare or aws when connection_profile is used")
	}
	if input.ProxyURL != "" {
		return nil, fmt.Errorf("proxy_url is unavailable for vault requests")
	}
	for name := range input.Headers {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "authorization", "proxy-authorization", "x-auth-key", "x-auth-email",
			"x-amz-security-token", "x-amz-date", "x-amz-content-sha256":
			return nil, fmt.Errorf("authentication headers are managed by the vault profile")
		}
	}
	c, err := vault.Resolve(ctx, kind, strings.TrimSpace(input.ConnectionProfile))
	if err != nil {
		return nil, err
	}
	return signProfile(ctx, req, kind, c, input.Body, time.Now().UTC())
}

func signProfile(ctx context.Context, req *http.Request, kind string, c vault.Credentials, body string, now time.Time) (func(string) string, error) {
	if req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Fragment != "" || req.URL.Hostname() != req.URL.Host {
		return nil, fmt.Errorf("vault requests require a canonical HTTPS URL without user info, explicit port, or fragment")
	}
	var secrets []string
	switch kind {
	case vault.Cloudflare:
		if req.URL.Host != "api.cloudflare.com" || !strings.HasPrefix(path.Clean(req.URL.Path), "/client/v4/") {
			return nil, fmt.Errorf("Cloudflare profiles are restricted to https://api.cloudflare.com/client/v4/")
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		secrets = []string{c.Token}
	case vault.AWS:
		endpoint, _ := url.Parse(c.Endpoint)
		if endpoint == nil || req.URL.Host != endpoint.Host {
			return nil, fmt.Errorf("request URL does not match this profile's fixed AWS HTTPS origin")
		}
		for param := range req.URL.Query() {
			switch strings.ToLower(param) {
			case "x-amz-credential", "x-amz-signature", "x-amz-security-token", "x-amz-algorithm":
				return nil, fmt.Errorf("AWS profile requests cannot carry presigned URL authentication")
			}
		}
		hash := sha256.Sum256([]byte(body))
		payloadHash := hex.EncodeToString(hash[:])
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
		signer := v4.NewSigner(func(o *v4.SignerOptions) {
			o.DisableURIPathEscaping = c.Service == "s3"
		})
		creds := aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken}
		if err := signer.SignHTTP(ctx, creds, req, payloadHash, c.Service, c.Region, now); err != nil {
			return nil, fmt.Errorf("could not sign AWS request")
		}
		secrets = []string{c.SecretAccessKey, c.SessionToken, c.AccessKeyID, req.Header.Get("Authorization")}
	default:
		return nil, fmt.Errorf("unsupported HTTP profile kind")
	}
	return func(text string) string {
		for _, secret := range secrets {
			if secret != "" {
				text = strings.ReplaceAll(text, secret, "[redacted]")
			}
		}
		return text
	}, nil
}
