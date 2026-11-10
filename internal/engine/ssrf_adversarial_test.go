package engine

import (
	"context"
	"net/netip"
	"os"
	"testing"
)

func TestParseLooseIPv4_And_SSRF(t *testing.T) {
	_ = os.Unsetenv("ALLOW_PRIVATE_TARGETS")

	evasiveTargets := []struct {
		input       string
		canonicalIP string
		restricted  bool
	}{
		{"0177.0.0.1", "127.0.0.1", true},       // Octal 127
		{"0x7f000001", "127.0.0.1", true},       // Hex DWORD
		{"0x7f.0.0.1", "127.0.0.1", true},       // Hex octet
		{"0177.0.0.0x1", "127.0.0.1", true},     // Mixed octal + hex
		{"127.1", "127.0.0.1", true},            // BSD short-form
		{"2130706433", "127.0.0.1", true},       // Decimal DWORD
		{"012.0.0.1", "10.0.0.1", true},         // Octal 10 (10.0.0.1 RFC 1918)
		{"0xa.0.0.1", "10.0.0.1", true},         // Hex 10 (10.0.0.1 RFC 1918)
		{"0.0.0.0", "0.0.0.0", true},            // Unspecified / Linux localhost
		{"::ffff:127.0.0.1", "127.0.0.1", true}, // IPv4-mapped IPv6
	}

	for _, tc := range evasiveTargets {
		t.Run(tc.input, func(t *testing.T) {
			var addr netip.Addr
			if parsed, err := netip.ParseAddr(tc.input); err == nil {
				addr = parsed
			} else if loose, ok := ParseLooseIPv4(tc.input); ok {
				addr = loose
			} else {
				t.Fatalf("Failed to parse evasive IP %q", tc.input)
			}

			if addr.Unmap().String() != tc.canonicalIP {
				t.Errorf("Parsed IP for %q = %s; want canonical %s", tc.input, addr.Unmap().String(), tc.canonicalIP)
			}

			if got := IsRestrictedIP(addr); got != tc.restricted {
				t.Errorf("IsRestrictedIP(%s) = %v; want %v", tc.input, got, tc.restricted)
			}

			// Verify SSRFDialContext directly rejects it
			_, err := SSRFDialContext(context.Background(), "tcp", tc.input+":80")
			if err == nil {
				t.Errorf("SSRFDialContext failed to block restricted evasive target %q", tc.input)
			}
		})
	}
}
