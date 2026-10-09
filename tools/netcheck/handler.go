// Package netcheck groups the small network diagnostics (public IP, DNS,
// TLS certificate) behind one tool, so they cost one schema instead of three.
package netcheck

import (
	"context"
	"fmt"
	"strings"

	"agent-tool/common"
	"agent-tool/tools/dnslookup"
	"agent-tool/tools/externalip"
	"agent-tool/tools/tlscheck"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type NetCheckInput struct {
	Operation   string `json:"operation" jsonschema:"external_ip, dns or tls,required"`
	Host        string `json:"host,omitempty" jsonschema:"Hostname (dns) or hostname/IP (tls)"`
	RecordType  string `json:"record_type,omitempty" jsonschema:"dns: A, AAAA, MX, CNAME, TXT, NS, SOA. Default: A"`
	UseDoH      *bool  `json:"use_doh,omitempty" jsonschema:"dns: use DNS over HTTPS. Default: true"`
	DoHEndpoint string `json:"doh_endpoint,omitempty" jsonschema:"dns: custom DoH endpoint URL. Default: Cloudflare"`
	Port        int    `json:"port,omitempty" jsonschema:"tls: port. Default: 443"`
	TimeoutSec  int    `json:"timeout_sec,omitempty" jsonschema:"tls: connection timeout seconds. Default: 10, Max: 30"`
}

type NetCheckOutput struct {
	Result string `json:"result"`
}

func Handle(ctx context.Context, req *mcp.CallToolRequest, input NetCheckInput) (*mcp.CallToolResult, NetCheckOutput, error) {
	var res *mcp.CallToolResult
	var err error
	switch op := strings.ToLower(strings.TrimSpace(input.Operation)); op {
	case "external_ip", "externalip", "ip":
		res, _, err = externalip.Handle(ctx, req, externalip.ExternalIPInput{})
	case "dns", "dnslookup":
		res, _, err = dnslookup.Handle(ctx, req, dnslookup.DNSLookupInput{Host: input.Host,
			RecordType: input.RecordType, UseDoH: input.UseDoH, DoHEndpoint: input.DoHEndpoint})
	case "tls", "tlscheck":
		res, _, err = tlscheck.Handle(ctx, req, tlscheck.TLSCheckInput{Host: input.Host,
			Port: input.Port, TimeoutSec: input.TimeoutSec})
	case "":
		return errorResult("operation is required: external_ip, dns (host, record_type) or tls (host, port)")
	default:
		return errorResult(fmt.Sprintf("unknown operation %q: use external_ip, dns (host, record_type) or tls (host, port). For an open-port check use portcheck", op))
	}
	if err != nil || res == nil {
		return res, NetCheckOutput{}, err
	}
	var text string
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			text = tc.Text
		}
	}
	return res, NetCheckOutput{Result: text}, nil
}

func Register(server *mcp.Server) {
	common.SafeAddTool(server, &mcp.Tool{
		Name: "netcheck",
		Description: `Network diagnostics, one operation per call:
- external_ip: your public IPv4 and IPv6 (dedicated detection services with fallback)
- dns: records for host (record_type A, AAAA, MX, CNAME, TXT, NS, SOA; DoH by default, use_doh=false for the system resolver)
- tls: certificate subject, issuer, expiry, SANs, TLS version and cipher for host:port (default 443)
For TCP reachability use portcheck; for HTTP use httpreq.`,
	}, Handle)
}

func errorResult(msg string) (*mcp.CallToolResult, NetCheckOutput, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}, NetCheckOutput{}, nil
}
