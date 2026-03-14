package common

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// --- Global DoH/ECH defaults ---
// Per-request no_doh/no_ech parameters can override these,
// but set_config allows changing the defaults globally.

var (
	enableDoH   = true
	enableDoHMu sync.RWMutex

	enableECH   = true
	enableECHMu sync.RWMutex
)

func GetEnableDoH() bool {
	enableDoHMu.RLock()
	defer enableDoHMu.RUnlock()
	return enableDoH
}

func SetEnableDoH(v bool) {
	enableDoHMu.Lock()
	defer enableDoHMu.Unlock()
	enableDoH = v
}

func GetEnableECH() bool {
	enableECHMu.RLock()
	defer enableECHMu.RUnlock()
	return enableECH
}

func SetEnableECH(v bool) {
	enableECHMu.Lock()
	defer enableECHMu.Unlock()
	enableECH = v
}

// HTTPClientConfig holds configuration for creating a secure HTTP client.
type HTTPClientConfig struct {
	TimeoutSec   int    // request timeout (default 30)
	MaxRedirects int    // max redirect hops (default 10)
	ProxyURL     string // "" = no proxy, "http://...", "socks5://..."
	EnableDoH    bool   // use DNS over HTTPS (default true)
	EnableECH    bool   // use Encrypted Client Hello (default true)
	DoHEndpoint  string // DoH server URL (default Cloudflare)
}

// NewHTTPClient creates an http.Client with DoH, ECH, proxy, and SSRF protection.
func NewHTTPClient(cfg HTTPClientConfig) (*http.Client, error) {
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 30
	}
	if cfg.MaxRedirects <= 0 {
		cfg.MaxRedirects = 10
	}

	transport, err := buildTransport(cfg)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout:   time.Duration(cfg.TimeoutSec) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return fmt.Errorf("too many redirects (max %d)", cfg.MaxRedirects)
			}
			// SSRF check on redirect target — use same resolver as DialContext
			host := req.URL.Hostname()
			var ips []net.IP
			var resolveErr error
			if cfg.EnableDoH {
				ips, resolveErr = ResolveDoHBoth(req.Context(), host, cfg.DoHEndpoint)
				if resolveErr != nil {
					ips, resolveErr = net.DefaultResolver.LookupIP(req.Context(), "ip", host)
				}
			} else {
				ips, resolveErr = net.DefaultResolver.LookupIP(req.Context(), "ip", host)
			}
			if resolveErr != nil {
				return fmt.Errorf("SSRF check: DNS resolution failed for redirect target %s: %w", host, resolveErr)
			}
			return ValidateResolvedIPWithPolicy(ips, GetAllowHTTPPrivate())
		},
	}
	return client, nil
}

// safeDialContext creates a DialContext function with SSRF protection.
// It resolves DNS, filters out cloud metadata IPs (preventing credential theft),
// and connects directly to resolved IPs (preventing DNS rebinding).
func safeDialContext(dialer *net.Dialer, enableDoH bool, dohEndpoint string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// Resolve DNS
		var ips []net.IP
		if enableDoH {
			ips, err = ResolveDoHBoth(ctx, host, dohEndpoint)
			if err != nil {
				// Fall back to system resolver
				ips, err = net.DefaultResolver.LookupIP(ctx, "ip", host)
			}
		} else {
			ips, err = net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}

		// Filter IPs by SSRF policy:
		// - Cloud metadata IPs: always blocked (non-configurable)
		// - Private IPs: blocked unless allow_http_private is true
		// Sort: IPv4 first (many networks lack IPv6 connectivity)
		allowPrivate := GetAllowHTTPPrivate()
		var safeIPv4, safeIPv6 []net.IP
		for _, ip := range ips {
			if IsCloudMetadataIP(ip) {
				continue
			}
			if !allowPrivate && IsPrivateIP(ip) {
				continue
			}
			if ip.To4() != nil {
				safeIPv4 = append(safeIPv4, ip)
			} else {
				safeIPv6 = append(safeIPv6, ip)
			}
		}
		safeIPs := append(safeIPv4, safeIPv6...)
		if len(safeIPs) == 0 {
			if allowPrivate {
				return nil, fmt.Errorf("SSRF blocked: all resolved IPs are cloud metadata addresses (%v)", ips)
			}
			return nil, fmt.Errorf("SSRF blocked: all resolved IPs are private/internal (%v). Use set_config to enable allow_http_private if intended", ips)
		}

		// Connect directly to resolved IPs (prevents DNS rebinding TOCTOU)
		var lastErr error
		for _, ip := range safeIPs {
			target := net.JoinHostPort(ip.String(), port)
			conn, err := dialer.DialContext(ctx, network, target)
			if err != nil {
				lastErr = err
				continue
			}
			return conn, nil
		}
		return nil, fmt.Errorf("connection failed to %s: %w", host, lastErr)
	}
}

// buildTransport creates the http.Transport with all security features.
func buildTransport(cfg HTTPClientConfig) (*http.Transport, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Base DialContext with DoH + SSRF protection
	ssrfDial := safeDialContext(dialer, cfg.EnableDoH, cfg.DoHEndpoint)
	transport.DialContext = ssrfDial

	// Apply proxy settings
	if cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}

		// Validate proxy host is not a cloud metadata endpoint
		proxyHost := proxyURL.Hostname()
		if proxyIP := net.ParseIP(proxyHost); proxyIP != nil {
			if IsCloudMetadataIP(proxyIP) {
				return nil, fmt.Errorf("SSRF blocked: proxy host %s is a cloud metadata address", proxyHost)
			}
		} else {
			resolvedIPs, err := net.LookupIP(proxyHost)
			if err != nil {
				return nil, fmt.Errorf("proxy host DNS resolution failed: %w", err)
			}
			if err := ValidateResolvedIPWithPolicy(resolvedIPs, GetAllowHTTPPrivate()); err != nil {
				return nil, fmt.Errorf("SSRF blocked: proxy host %s: %w", proxyHost, err)
			}
		}

		switch proxyURL.Scheme {
		case "http", "https":
			transport.Proxy = http.ProxyURL(proxyURL)
			// Note: HTTP proxy relays the connection, so DialContext SSRF check
			// applies to the proxy host. The proxy itself handles the final connection.
			// Proxy users accept this trust delegation.
		case "socks5", "socks5h":
			socksDialer, err := proxy.FromURL(proxyURL, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("SOCKS5 proxy setup: %w", err)
			}
			ctxDialer, ok := socksDialer.(proxy.ContextDialer)
			if !ok {
				return nil, fmt.Errorf("SOCKS5 proxy does not support DialContext")
			}
			// FIX S1: Wrap SOCKS5 dialer with SSRF check instead of replacing
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, splitErr := net.SplitHostPort(addr)
				if splitErr != nil {
					return nil, splitErr
				}
				// Resolve and validate target (not just the proxy)
				var ips []net.IP
				var resolveErr error
				if cfg.EnableDoH {
					ips, resolveErr = ResolveDoHBoth(ctx, host, cfg.DoHEndpoint)
					if resolveErr != nil {
						ips, resolveErr = net.DefaultResolver.LookupIP(ctx, "ip", host)
					}
				} else {
					ips, resolveErr = net.DefaultResolver.LookupIP(ctx, "ip", host)
				}
				if resolveErr != nil {
					return nil, fmt.Errorf("DNS resolution failed: %w", resolveErr)
				}
				// Filter IPs by same policy as safeDialContext
				allowPrivate := GetAllowHTTPPrivate()
				var safeIPs []net.IP
				for _, ip := range ips {
					if IsCloudMetadataIP(ip) {
						continue
					}
					if !allowPrivate && IsPrivateIP(ip) {
						continue
					}
					safeIPs = append(safeIPs, ip)
				}
				if len(safeIPs) == 0 {
					if !allowPrivate {
						return nil, fmt.Errorf("SSRF blocked (SOCKS5 target): all resolved IPs for %s are private or cloud metadata addresses", host)
					}
					return nil, fmt.Errorf("SSRF blocked (SOCKS5 target): all resolved IPs for %s are cloud metadata addresses", host)
				}
				// Use resolved IP to prevent DNS rebinding — the SOCKS5 proxy
				// receives the validated IP, not the hostname that could re-resolve
				// to a different (potentially malicious) address.
				_, port, _ := net.SplitHostPort(addr)
				safeAddr := net.JoinHostPort(safeIPs[0].String(), port)
				return ctxDialer.DialContext(ctx, network, safeAddr)
			}
		default:
			return nil, fmt.Errorf("unsupported proxy scheme: %s (use http, https, or socks5)", proxyURL.Scheme)
		}
	}

	return transport, nil
}

// DoRequestWithECH performs an HTTP request with ECH support.
// If ECH fails, it automatically retries without ECH.
// Note: ECH fallback requires the request body to be re-readable.
// If req has a body but no GetBody, ECH is skipped to avoid body consumption issues.
func DoRequestWithECH(ctx context.Context, client *http.Client, req *http.Request, enableECH bool) (*http.Response, error) {
	if !enableECH {
		return client.Do(req)
	}

	// If request has body but can't be re-read, skip ECH to avoid body reuse issues
	if req.Body != nil && req.GetBody == nil {
		return client.Do(req)
	}

	// Try to fetch ECH config for the target host
	echConfig, err := FetchECHConfigList(ctx, req.URL.Hostname(), "")
	if err != nil || len(echConfig) == 0 {
		// No ECH config available, proceed without ECH
		return client.Do(req)
	}

	// Clone transport and set ECH config
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return client.Do(req)
	}

	echTransport := transport.Clone()
	if echTransport.TLSClientConfig == nil {
		echTransport.TLSClientConfig = &tls.Config{}
	}
	echTransport.TLSClientConfig.EncryptedClientHelloConfigList = echConfig

	echClient := &http.Client{
		Timeout:       client.Timeout,
		Transport:     echTransport,
		CheckRedirect: client.CheckRedirect,
	}

	resp, err := echClient.Do(req)
	if err != nil {
		// ECH failed — restore body for retry if possible
		if req.GetBody != nil {
			req.Body, _ = req.GetBody()
		}
		// Retry without ECH (automatic fallback)
		if _, ok := err.(*tls.ECHRejectionError); ok {
			return client.Do(req)
		}
		// Other TLS errors might also be ECH-related, try fallback
		resp2, err2 := client.Do(req)
		if err2 != nil {
			return nil, err // return original error
		}
		return resp2, nil
	}
	return resp, nil
}
