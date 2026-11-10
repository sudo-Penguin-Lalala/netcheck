package middleware

import (
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

var defaultTrustedCIDRs = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"::1/128",
	"fc00::/7",
}

func getTrustedCIDRs() []netip.Prefix {
	trustedEnv := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES"))
	var cidrStrs []string
	if trustedEnv != "" {
		for _, part := range strings.Split(trustedEnv, ",") {
			p := strings.TrimSpace(part)
			if p != "" {
				cidrStrs = append(cidrStrs, p)
			}
		}
	} else {
		cidrStrs = defaultTrustedCIDRs
	}

	var prefixes []netip.Prefix
	for _, cidr := range cidrStrs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			prefixes = append(prefixes, prefix)
		} else if addr, err := netip.ParseAddr(cidr); err == nil {
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
		}
	}
	return prefixes
}

func isTrustedRemoteAddr(remoteAddr string, trustedPrefixes []netip.Prefix) bool {
	addr, err := netip.ParseAddr(remoteAddr)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range trustedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ExtractClientIP returns client IP, trusting forwarded headers only from TRUSTED_PROXIES peers.
func ExtractClientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	if !isTrustedRemoteAddr(remoteHost, getTrustedCIDRs()) {
		return remoteHost
	}

	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		if _, err := netip.ParseAddr(cf); err == nil {
			return cf
		}
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, p := range strings.Split(xff, ",") {
			if addr, err := netip.ParseAddr(strings.TrimSpace(p)); err == nil {
				return addr.String()
			}
		}
	}

	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if _, err := netip.ParseAddr(xri); err == nil {
			return xri
		}
	}

	return remoteHost
}
