package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/sudo-Penguin-Lalala/netcheck/internal/engine"
	"github.com/sudo-Penguin-Lalala/netcheck/internal/middleware"
)

func TestVector1_EvasiveSSRFPayloads(t *testing.T) {
	_ = os.Unsetenv("ALLOW_PRIVATE_TARGETS")

	evasiveTargets := []string{
		"0177.0.0.1",
		"0x7f000001",
		"0x7f.0.0.1",
		"127.1",
		"2130706433",
		"0.0.0.0",
		"::ffff:127.0.0.1",
		"012.0.0.1",
	}

	for _, target := range evasiveTargets {
		t.Run("Ping_"+target, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"target": target})
			req := httptest.NewRequest(http.MethodPost, "/api/ping", bytes.NewReader(body))
			rec := httptest.NewRecorder()

			PingHandler(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("Expected HTTP 403 Forbidden for target %q, got %d: %s", target, rec.Code, rec.Body.String())
			}

			var res map[string]string
			_ = json.Unmarshal(rec.Body.Bytes(), &res)
			if res["error"] != "private_blocked" {
				t.Errorf("Expected 'private_blocked' error code for %q, got %q", target, res["error"])
			}
		})

		t.Run("Port_"+target, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"target": target, "port": 80})
			req := httptest.NewRequest(http.MethodPost, "/api/port", bytes.NewReader(body))
			rec := httptest.NewRecorder()

			PortHandler(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("Expected HTTP 403 Forbidden for target %q, got %d: %s", target, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestVector2_WhoisCaseNormalizationAndDedup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in -short mode")
	}
	// Query 1 with mixed-case domain
	body1 := []byte(`{"target": "CloudFlare.COM"}`)
	req1 := httptest.NewRequest(http.MethodPost, "/api/whois", bytes.NewReader(body1))
	rec1 := httptest.NewRecorder()

	WhoisHandler(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("Expected 200 for mixed case, got %d", rec1.Code)
	}

	// Query 2 with lower-case domain must hit cache without triggering a second upstream query
	body2 := []byte(`{"target": "cloudflare.com"}`)
	req2 := httptest.NewRequest(http.MethodPost, "/api/whois", bytes.NewReader(body2))
	rec2 := httptest.NewRecorder()

	WhoisHandler(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("Expected 200 for lower-case cached hit, got %d", rec2.Code)
	}

	// Verify both responses are identical
	if rec1.Body.String() != rec2.Body.String() {
		t.Errorf("Expected identical response from normalized cache key")
	}
}

func TestVector3_RateLimiterProxySpoofingRejection(t *testing.T) {
	_ = os.Unsetenv("TRUSTED_PROXIES")

	// Direct attacker connection from untrusted public IP
	req := httptest.NewRequest(http.MethodGet, "/api/ip", nil)
	req.RemoteAddr = "198.51.100.99:43210"        // Untrusted public WAN IP
	req.Header.Set("CF-Connecting-IP", "1.1.1.1") // Attacker attempting to spoof Cloudflare DNS
	req.Header.Set("X-Forwarded-For", "8.8.8.8")  // Attacker attempting to spoof Google DNS

	clientIP := middleware.ExtractClientIP(req)

	// MUST strictly reject both spoofed headers and return the raw peer socket IP
	if clientIP != "198.51.100.99" {
		t.Fatalf("Security failure: Untrusted remoteAddr successfully spoofed client IP to %q", clientIP)
	}
}

func TestVector4_Globalping502HTML_NoPanic(t *testing.T) {
	// Mock an upstream server returning HTML with a 502 Bad Gateway status
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><body><h1>502 Bad Gateway</h1><p>Cloudflare outage</p></body></html>"))
	}))
	defer ts.Close()

	_ = os.Setenv("GLOBALPING_API", ts.URL)
	defer os.Unsetenv("GLOBALPING_API")

	_, err := engine.SubmitMeasurement(context.Background(), map[string]string{"type": "ping", "target": "1.1.1.1"})
	if err == nil {
		t.Fatal("Expected error from 502 upstream, got nil")
	}

	var gpErr *engine.GlobalpingError
	if !errors.As(err, &gpErr) {
		t.Fatalf("Expected *engine.GlobalpingError, got %T: %v", err, err)
	}
	if gpErr.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", gpErr.StatusCode)
	}
}
