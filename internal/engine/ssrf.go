package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	ErrRestrictedIP = errors.New("403 Forbidden: Target resolves to restricted private or reserved IP")

	cgnatPrefix      = netip.MustParsePrefix("100.64.0.0/10")
	benchmarkingIPv4 = netip.MustParsePrefix("198.18.0.0/15")
	docNet1          = netip.MustParsePrefix("192.0.2.0/24")
	docNet2          = netip.MustParsePrefix("198.51.100.0/24")
	docNet3          = netip.MustParsePrefix("203.0.113.0/24")
	classEIPv4       = netip.MustParsePrefix("240.0.0.0/4")
	thisNetworkIPv4  = netip.MustParsePrefix("0.0.0.0/8")
	docIPv6          = netip.MustParsePrefix("2001:db8::/32")
	nat64Prefix      = netip.MustParsePrefix("64:ff9b::/96")
	nat64LocalPrefix = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFourPrefix  = netip.MustParsePrefix("2002::/16")
)

func AllowPrivateTargets() bool {
	v := strings.TrimSpace(os.Getenv("ALLOW_PRIVATE_TARGETS"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func IsRestrictedIP(addr netip.Addr) bool {
	// Unmap ::ffff:127.0.0.1 to catch dual-stack loopbacks
	addr = addr.Unmap()
	if !addr.IsValid() {
		return true
	}

	if addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return true
	}

	if addr.Is4() {
		return cgnatPrefix.Contains(addr) ||
			benchmarkingIPv4.Contains(addr) ||
			docNet1.Contains(addr) ||
			docNet2.Contains(addr) ||
			docNet3.Contains(addr) ||
			classEIPv4.Contains(addr) ||
			thisNetworkIPv4.Contains(addr)
	}

	if nat64Prefix.Contains(addr) {
		b := addr.As16()
		return IsRestrictedIP(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	if nat64LocalPrefix.Contains(addr) {
		b := addr.As16()
		return IsRestrictedIP(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	if sixToFourPrefix.Contains(addr) {
		b := addr.As16()
		return IsRestrictedIP(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
	}

	return docIPv6.Contains(addr)
}

// ParseLooseIPv4 handles legacy POSIX inet_aton formats (octal, hex, dwords, short notation)
// that bypass netip.ParseAddr but are treated as loopback/LAN by C socket libraries.
func ParseLooseIPv4(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, ":") {
		return netip.Addr{}, false
	}

	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}

	var vals []uint64
	for _, p := range parts {
		if p == "" {
			return netip.Addr{}, false
		}
		var val uint64
		var err error
		if strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X") {
			val, err = strconv.ParseUint(p[2:], 16, 64)
		} else if strings.HasPrefix(p, "0") && len(p) > 1 {
			val, err = strconv.ParseUint(p, 8, 64)
		} else {
			val, err = strconv.ParseUint(p, 10, 64)
		}
		if err != nil {
			return netip.Addr{}, false
		}
		vals = append(vals, val)
	}

	var ipInt uint64
	switch len(vals) {
	case 1: // DWORD / 32-bit int (2130706433 or 0x7f000001)
		if vals[0] > 0xFFFFFFFF {
			return netip.Addr{}, false
		}
		ipInt = vals[0]
	case 2: // a.b (a: 8-bit, b: 24-bit)
		if vals[0] > 0xFF || vals[1] > 0xFFFFFF {
			return netip.Addr{}, false
		}
		ipInt = (vals[0] << 24) | vals[1]
	case 3: // a.b.c (a: 8-bit, b: 8-bit, c: 16-bit)
		if vals[0] > 0xFF || vals[1] > 0xFF || vals[2] > 0xFFFF {
			return netip.Addr{}, false
		}
		ipInt = (vals[0] << 24) | (vals[1] << 16) | vals[2]
	case 4: // a.b.c.d
		if vals[0] > 0xFF || vals[1] > 0xFF || vals[2] > 0xFF || vals[3] > 0xFF {
			return netip.Addr{}, false
		}
		ipInt = (vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | vals[3]
	default:
		return netip.Addr{}, false
	}

	b := [4]byte{
		byte((ipInt >> 24) & 0xFF),
		byte((ipInt >> 16) & 0xFF),
		byte((ipInt >> 8) & 0xFF),
		byte(ipInt & 0xFF),
	}
	return netip.AddrFrom4(b), true
}

// SSRFDialContext dials the resolved IP directly to eliminate TOCTOU DNS rebinding.
func SSRFDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	allowPrivate := AllowPrivateTargets()

	if ip, err := netip.ParseAddr(host); err == nil {
		if !allowPrivate && IsRestrictedIP(ip) {
			return nil, ErrRestrictedIP
		}
		dialer := net.Dialer{Timeout: 10 * time.Second}
		return dialer.DialContext(ctx, network, addr)
	}

	if ip, ok := ParseLooseIPv4(host); ok {
		if !allowPrivate && IsRestrictedIP(ip) {
			return nil, ErrRestrictedIP
		}
		dialer := net.Dialer{Timeout: 10 * time.Second}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns resolution failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %q", host)
	}

	var safeIPs []netip.Addr
	for _, ipAddr := range ips {
		addr, ok := netip.AddrFromSlice(ipAddr.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()

		if !allowPrivate && IsRestrictedIP(addr) {
			return nil, fmt.Errorf("%w: %s (%s)", ErrRestrictedIP, host, addr)
		}
		safeIPs = append(safeIPs, addr)
	}

	if len(safeIPs) == 0 {
		return nil, fmt.Errorf("no valid IP addresses for %q", host)
	}

	var chosenIP netip.Addr
	for _, ip := range safeIPs {
		if network == "tcp4" && ip.Is4() {
			chosenIP = ip
			break
		}
		if network == "tcp6" && ip.Is6() {
			chosenIP = ip
			break
		}
	}
	if !chosenIP.IsValid() {
		chosenIP = safeIPs[0]
	}

	dialer := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(chosenIP.String(), port))
}
