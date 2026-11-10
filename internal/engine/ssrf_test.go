package engine

import (
	"context"
	"net/netip"
	"os"
	"testing"
)

func TestIsRestrictedIP(t *testing.T) {
	tests := []struct {
		ip         string
		restricted bool
	}{
		// IPv4 Private & Loopback
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"169.254.1.1", true}, // Link-local
		{"100.64.0.1", true},  // CGNAT
		{"0.0.0.0", true},      // Unspecified
		{"224.0.0.1", true},    // Multicast

		// IPv6 Private & Loopback
		{"::1", true},
		{"::", true},
		{"fc00::1", true},   // ULA
		{"fe80::1", true},   // Link-local
		{"ff02::1", true},   // Multicast
		{"2001:db8::1", true}, // Documentation

		// IPv4-mapped IPv6 evasion attacks
		{"::ffff:127.0.0.1", true},
		{"::ffff:192.168.1.1", true},
		{"::ffff:10.0.0.1", true},

		// Public Safe IPs
		{"1.1.1.1", false},
		{"8.8.8.8", false},
		{"9.9.9.9", false},
		{"2606:4700:4700::1111", false},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		addr, err := netip.ParseAddr(tt.ip)
		if err != nil {
			t.Fatalf("Failed to parse IP %s: %v", tt.ip, err)
		}
		got := IsRestrictedIP(addr)
		if got != tt.restricted {
			t.Errorf("IsRestrictedIP(%s) = %v; want %v", tt.ip, got, tt.restricted)
		}
	}
}

func TestSSRFDialContext_BlocksPrivate(t *testing.T) {
	_ = os.Unsetenv("ALLOW_PRIVATE_TARGETS")

	ctx := context.Background()

	// Should reject direct loopback IP
	_, err := SSRFDialContext(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("Expected error dialing 127.0.0.1, got nil")
	}

	// Should reject localhost hostname resolution to loopback
	_, err = SSRFDialContext(ctx, "tcp", "localhost:80")
	if err == nil {
		t.Fatal("Expected error dialing localhost, got nil")
	}
}

func TestNormalizeLocation(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "world"},
		{"world", "world"},
		{"WORLD", "world"},
		{"as", "AS"},
		{"eu", "EU"},
		{"na", "NA"},
		{"invalid", "world"},
	}

	for _, tt := range tests {
		got := NormalizeLocation(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeLocation(%q) = %q; want %q", tt.input, got, tt.want)
		}
	}
}
