package common

import (
	"fmt"
	"net"
)

// privateRanges contains all private, loopback, and link-local CIDR ranges.
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // link-local
		"0.0.0.0/8",      // current network
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 ULA
	}
	for _, cidr := range cidrs {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet != nil {
			privateRanges = append(privateRanges, ipNet)
		}
	}
}

// IsPrivateIP checks if an IP address is private, loopback, or link-local.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true // treat nil as unsafe
	}
	// Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to 4-byte IPv4
	// so that IPv4 CIDR ranges match correctly.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateResolvedIP checks that no resolved IPs are SSRF targets.
// Returns error if any IP is private (strict mode to prevent mixed-IP attacks).
func ValidateResolvedIP(ips []net.IP) error {
	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses resolved")
	}
	for _, ip := range ips {
		if IsPrivateIP(ip) {
			return fmt.Errorf("SSRF blocked: resolved IP %s is private/internal", ip)
		}
	}
	return nil
}
