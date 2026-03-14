package common

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

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
			return ValidateResolvedIP(ips)
		},
	}
	return client, nil
}

// safeDialContext creates a DialContext function with SSRF protection.
// It resolves DNS, validates IPs against SSRF rules, filters out private IPs,
// and connects directly to resolved public IPs (preventing DNS rebinding).
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

		// FIX S5+S6: Filter out private IPs instead of just checking "at least one public"
		// Sort: IPv4 first, then IPv6 (many networks lack IPv6 connectivity)
		var publicIPv4, publicIPv6 []net.IP
		for _, ip := range ips {
			if IsPrivateIP(ip) {
				continue
			}
			if ip.To4() != nil {
				publicIPv4 = append(publicIPv4, ip)
			} else {
				publicIPv6 = append(publicIPv6, ip)
			}
		}
		publicIPs := append(publicIPv4, publicIPv6...)
		if len(publicIPs) == 0 {
			return nil, fmt.Errorf("SSRF blocked: all resolved IPs are private/internal (%v)", ips)
		}

		// FIX S5 (TOCTOU): Connect directly to resolved public IPs (no re-resolution)
		var lastErr error
		for _, ip := range publicIPs {
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

		// Validate proxy host itself is not private
		proxyHost := proxyURL.Hostname()
		if proxyIP := net.ParseIP(proxyHost); proxyIP != nil {
			if IsPrivateIP(proxyIP) {
				return nil, fmt.Errorf("SSRF blocked: proxy host %s is a private IP", proxyHost)
			}
		} else {
			// Domain name — resolve and check
			resolvedIPs, err := net.LookupIP(proxyHost)
			if err != nil {
				return nil, fmt.Errorf("proxy host DNS resolution failed: %w", err)
			}
			if err := ValidateResolvedIP(resolvedIPs); err != nil {
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
				// SSRF check on target (not proxy)
				if err := ValidateResolvedIP(ips); err != nil {
					return nil, fmt.Errorf("SSRF blocked (SOCKS5 target): %w", err)
				}
				// SOCKS5 proxy handles the actual connection
				return ctxDialer.DialContext(ctx, network, addr)
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
