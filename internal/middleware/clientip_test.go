package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestExtractClientIP_Defaults(t *testing.T) {
	_ = os.Unsetenv("TRUSTED_PROXIES")

	// IPv4 loopback
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("CF-Connecting-IP", "203.0.113.50")
	if ip := ExtractClientIP(req); ip != "203.0.113.50" {
		t.Fatalf("expected 203.0.113.50 from 127.0.0.1 peer, got %s", ip)
	}

	// IPv6 loopback
	reqV6 := httptest.NewRequest(http.MethodGet, "/", nil)
	reqV6.RemoteAddr = "[::1]:54321"
	reqV6.Header.Set("CF-Connecting-IP", "203.0.113.51")
	if ip := ExtractClientIP(reqV6); ip != "203.0.113.51" {
		t.Fatalf("expected 203.0.113.51 from ::1 peer, got %s", ip)
	}

	// Docker bridge subnet 172.17.0.1
	reqDocker := httptest.NewRequest(http.MethodGet, "/", nil)
	reqDocker.RemoteAddr = "172.17.0.1:54321"
	reqDocker.Header.Set("CF-Connecting-IP", "203.0.113.52")
	if ip := ExtractClientIP(reqDocker); ip != "203.0.113.52" {
		t.Fatalf("expected 203.0.113.52 from 172.17.0.1 peer, got %s", ip)
	}

	// Untrusted public peer should NOT have headers trusted
	reqUntrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	reqUntrusted.RemoteAddr = "198.51.100.1:54321"
	reqUntrusted.Header.Set("CF-Connecting-IP", "203.0.113.53")
	if ip := ExtractClientIP(reqUntrusted); ip != "198.51.100.1" {
		t.Fatalf("expected untrusted peer 198.51.100.1, got %s", ip)
	}
}

func TestExtractClientIP_Wildcard(t *testing.T) {
	_ = os.Setenv("TRUSTED_PROXIES", "*")
	defer os.Unsetenv("TRUSTED_PROXIES")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.99:54321"
	req.Header.Set("CF-Connecting-IP", "203.0.113.99")
	if ip := ExtractClientIP(req); ip != "203.0.113.99" {
		t.Fatalf("expected 203.0.113.99 with wildcard proxy, got %s", ip)
	}
}

func TestExtractClientIP_HeadersPrecedence(t *testing.T) {
	_ = os.Unsetenv("TRUSTED_PROXIES")

	// CF-Connecting-IP takes precedence over X-Forwarded-For
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("CF-Connecting-IP", "203.0.113.1")
	req.Header.Set("X-Forwarded-For", "203.0.113.2, 10.0.0.1")
	if ip := ExtractClientIP(req); ip != "203.0.113.1" {
		t.Fatalf("expected CF-Connecting-IP to take precedence, got %s", ip)
	}

	// X-Forwarded-For when CF-Connecting-IP is absent
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "127.0.0.1:54321"
	req2.Header.Set("X-Forwarded-For", "203.0.113.2, 10.0.0.1")
	if ip := ExtractClientIP(req2); ip != "203.0.113.2" {
		t.Fatalf("expected first X-Forwarded-For IP 203.0.113.2, got %s", ip)
	}
}
