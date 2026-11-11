package middleware

import (
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
)

var defaultTrustedCIDRs = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"::1/128",
	"fc00::/7",
}

var (
	trustedMu      sync.RWMutex
	lastTrustedEnv string
	cachedPrefixes []netip.Prefix
)

func getTrustedCIDRs() []netip.Prefix {
	trustedEnv := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES"))

	trustedMu.RLock()
	if cachedPrefixes != nil && trustedEnv == lastTrustedEnv {
		res := cachedPrefixes
		trustedMu.RUnlock()
		return res
	}
	trustedMu.RUnlock()

	trustedMu.Lock()
	defer trustedMu.Unlock()

	if cachedPrefixes != nil && trustedEnv == lastTrustedEnv {
		return cachedPrefixes
	}

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
		if cidr == "*" || cidr == "all" {
			prefixes = append(prefixes,
				netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				netip.PrefixFrom(netip.IPv6Unspecified(), 0),
			)
			continue
		}
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

	lastTrustedEnv = trustedEnv
	cachedPrefixes = prefixes
	return prefixes
}

func isTrustedAddr(addr netip.Addr, trustedPrefixes []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, prefix := range trustedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func isTrustedRemoteAddr(remoteAddr string, trustedPrefixes []netip.Prefix) bool {
	addr, err := netip.ParseAddr(remoteAddr)
	if err != nil {
		return false
	}
	return isTrustedAddr(addr, trustedPrefixes)
}

// ExtractClientIP returns client IP, trusting forwarded headers only from TRUSTED_PROXIES peers.
// Uses RFC 7239 right-to-left traversal for X-Forwarded-For to prevent leftmost spoofing bypasses.
func ExtractClientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	trusted := getTrustedCIDRs()
	if !isTrustedRemoteAddr(remoteHost, trusted) {
		return remoteHost
	}

	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		if addr, err := netip.ParseAddr(cf); err == nil {
			return addr.Unmap().String()
		}
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Traverse right-to-left: first untrusted IP in the chain is the client
		for i := len(parts) - 1; i >= 0; i-- {
			ipStr := strings.TrimSpace(parts[i])
			addr, err := netip.ParseAddr(ipStr)
			if err != nil {
				continue
			}
			addr = addr.Unmap()
			if !isTrustedAddr(addr, trusted) {
				return addr.String()
			}
		}
		// If all IPs in chain are in trusted proxies, return the leftmost client IP
		if len(parts) > 0 {
			if addr, err := netip.ParseAddr(strings.TrimSpace(parts[0])); err == nil {
				return addr.Unmap().String()
			}
		}
	}

	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if addr, err := netip.ParseAddr(xri); err == nil {
			return addr.Unmap().String()
		}
	}

	return remoteHost
}
