package common

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

const (
	// DefaultDoHEndpoint is the Cloudflare DNS over HTTPS endpoint.
	DefaultDoHEndpoint = "https://cloudflare-dns.com/dns-query"

	dohTimeout = 5 * time.Second
)

// dohHTTPClient is a dedicated client for DoH queries.
// It uses the system resolver (not DoH) to avoid circular dependency.
var dohHTTPClient = &http.Client{
	Timeout: dohTimeout,
	Transport: &http.Transport{
		// Use system DNS resolver for the DoH endpoint itself
		DialContext: (&net.Dialer{
			Timeout: 3 * time.Second,
		}).DialContext,
	},
}

// ResolveDoH resolves a hostname using DNS over HTTPS (RFC 8484).
// Returns resolved IP addresses. qtype should be dns.TypeA or dns.TypeAAAA.
func ResolveDoH(ctx context.Context, host string, qtype uint16, endpoint string) ([]net.IP, error) {
	if endpoint == "" {
		endpoint = DefaultDoHEndpoint
	}

	// Build DNS wire-format query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.RecursionDesired = true

	wireData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS query: %w", err)
	}

	// Send as HTTP POST with application/dns-message
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Body = io.NopCloser(bytesReader(wireData))
	req.ContentLength = int64(len(wireData))

	resp, err := dohHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH response status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}

	// Parse DNS response
	var respMsg dns.Msg
	if err := respMsg.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack DNS response: %w", err)
	}

	var ips []net.IP
	for _, ans := range respMsg.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			ips = append(ips, rr.A)
		case *dns.AAAA:
			ips = append(ips, rr.AAAA)
		}
	}

	return ips, nil
}

// ResolveDoHBoth resolves both A and AAAA records via DoH.
func ResolveDoHBoth(ctx context.Context, host string, endpoint string) ([]net.IP, error) {
	// Try A and AAAA in sequence (simple, avoids goroutine complexity)
	var allIPs []net.IP

	ips4, err4 := ResolveDoH(ctx, host, dns.TypeA, endpoint)
	if err4 != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	allIPs = append(allIPs, ips4...)

	ips6, err6 := ResolveDoH(ctx, host, dns.TypeAAAA, endpoint)
	if err6 != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	allIPs = append(allIPs, ips6...)

	if len(allIPs) == 0 {
		return nil, fmt.Errorf("DoH: no addresses found for %s", host)
	}
	return allIPs, nil
}

// FetchECHConfigList fetches the ECH configuration from DNS HTTPS record (type 65).
// Returns the raw ECHConfigList bytes, or nil if not available.
func FetchECHConfigList(ctx context.Context, host string, endpoint string) ([]byte, error) {
	if endpoint == "" {
		endpoint = DefaultDoHEndpoint
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeHTTPS)
	msg.RecursionDesired = true

	wireData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack HTTPS query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Body = io.NopCloser(bytesReader(wireData))
	req.ContentLength = int64(len(wireData))

	resp, err := dohHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTPS record query status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}

	var respMsg dns.Msg
	if err := respMsg.Unpack(body); err != nil {
		return nil, err
	}

	// Look for HTTPS RR with ECH SvcParam (key 5)
	for _, ans := range respMsg.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			for _, kv := range https.Value {
				if kv.Key() == dns.SVCB_ECHCONFIG {
					if ech, ok := kv.(*dns.SVCBECHConfig); ok {
						return ech.ECH, nil
					}
				}
			}
		}
	}

	return nil, nil // no ECH config available (not an error)
}

// bytesReader is a simple io.Reader wrapper for a byte slice.
type bytesReaderType struct {
	data []byte
	pos  int
}

func (r *bytesReaderType) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func bytesReader(data []byte) io.Reader {
	return &bytesReaderType{data: data}
}
