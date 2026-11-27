package httpreq

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"agent-tool/internal/vault"
)

func TestVaultRequestsUseOnlyConfiguredOrigins(t *testing.T) {
	c := vault.Credentials{Token: "token-fixture", Endpoint: "https://sts.us-east-1.amazonaws.com",
		AccessKeyID: "access-fixture", SecretAccessKey: "signing-fixture", SessionToken: "session-fixture", Region: "us-east-1", Service: "sts"}
	for _, tc := range []struct {
		kind   string
		url    string
		marker string
	}{
		{vault.Cloudflare, "https://api.cloudflare.com/client/v4/zones", "Bearer token-fixture"},
		{vault.Cloudflare, "https://api.cloudflare.com/client/v4/../../../unrelated", ""},
		{vault.Cloudflare, "https://api.cloudflare.com.example.invalid/client/v4/zones", ""},
		{vault.AWS, "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity", "AWS4-HMAC-SHA256"},
		{vault.AWS, "https://s3.us-east-1.amazonaws.com/", ""},
		{vault.AWS, "https://sts.us-east-1.amazonaws.com/?X-Amz-Signature=already-signed", ""},
	} {
		req, err := http.NewRequest("GET", tc.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		redact, err := signProfile(t.Context(), req, tc.kind, c, "", time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC))
		auth := req.Header.Get("Authorization")
		if tc.marker == "" {
			if err == nil || auth != "" {
				t.Fatalf("authorization reached disallowed destination %s", tc.url)
			}
			continue
		}
		if err != nil || !strings.HasPrefix(auth, tc.marker) {
			t.Fatalf("authentication missing for %s: %v", tc.kind, err)
		}
		if tc.kind == vault.AWS && req.Header.Get("X-Amz-Security-Token") != c.SessionToken {
			t.Fatal("AWS session token missing from signed request")
		}
		if strings.Contains(redact(auth+" "+req.Header.Get("X-Amz-Security-Token")), "fixture") {
			t.Fatal("credential leaked through response redaction")
		}
	}
}
