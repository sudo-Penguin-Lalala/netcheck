package handlers

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestDnsHandler_A_Record(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in -short mode")
	}
	body := []byte(`{"host": "one.one.one.one", "type": "A"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/dns", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	DnsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var res struct {
		Records  []string `json:"records"`
		TTL      uint32   `json:"ttl"`
		Resolver string   `json:"resolver"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("Failed to decode DNS response: %v", err)
	}

	if len(res.Records) == 0 {
		t.Fatal("Expected at least one A record for one.one.one.one")
	}

	found := false
	for _, r := range res.Records {
		if r == "1.1.1.1" || r == "1.0.0.1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected 1.1.1.1 in records, got %v", res.Records)
	}
}

func TestDnsHandler_NXDOMAIN(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in -short mode")
	}
	body := []byte(`{"host": "this-domain-definitely-does-not-exist-123456789.com", "type": "A"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/dns", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	DnsHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400 for NXDOMAIN, got %d", rec.Code)
	}

	var res map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res["error"] != "nxdomain" {
		t.Errorf("Expected error 'nxdomain', got %q", res["error"])
	}
}

func TestRdnsHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in -short mode")
	}
	body := []byte(`{"ip": "1.1.1.1"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/rdns", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	RdnsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for rDNS 1.1.1.1, got %d: %s", rec.Code, rec.Body.String())
	}

	var res struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("Failed to decode rDNS response: %v", err)
	}

	if res.Hostname != "one.one.one.one" {
		t.Errorf("Expected hostname 'one.one.one.one', got %q", res.Hostname)
	}
}

func TestValidateResolverSecurity_PinnedIP(t *testing.T) {
	ctx := t.Context()

	// IP literal should be preserved
	pinned, err := validateResolverSecurity(ctx, "8.8.8.8:53")
	if err != nil {
		t.Fatalf("Unexpected error for 8.8.8.8:53: %v", err)
	}
	if pinned != "8.8.8.8:53" {
		t.Errorf("Expected '8.8.8.8:53', got %q", pinned)
	}

	// Restricted IP should fail
	_, err = validateResolverSecurity(ctx, "127.0.0.1:53")
	if err == nil {
		t.Fatal("Expected error for loopback resolver 127.0.0.1:53, got nil")
	}

	// Hostname should resolve and return a pinned IP literal, NOT the hostname string
	if !testing.Short() {
		resolved, err := validateResolverSecurity(ctx, "one.one.one.one:53")
		if err != nil {
			t.Fatalf("Failed to resolve one.one.one.one:53: %v", err)
		}
		host, port, err := net.SplitHostPort(resolved)
		if err != nil {
			t.Fatalf("Returned address %q is not host:port: %v", resolved, err)
		}
		if port != "53" {
			t.Errorf("Expected port 53, got %q", port)
		}
		if _, err := netip.ParseAddr(host); err != nil {
			t.Errorf("Returned host %q is not a pinned IP literal (DNS Rebinding risk): %v", host, err)
		}
	}
}

func TestRdnsHandler_SSRF_Blocked(t *testing.T) {
	body := []byte(`{"ip": "1.1.1.1", "server": "127.0.0.1:53"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/rdns", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	RdnsHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected status 403 Forbidden for loopback resolver, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDnsHandler_NODATA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in -short mode")
	}
	body := []byte(`{"host": "one.one.one.one", "type": "SRV"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/dns", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	DnsHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400 for NODATA, got %d", rec.Code)
	}

	var res map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res["error"] != "no_answer" {
		t.Errorf("Expected error 'no_answer', got %q", res["error"])
	}
}

func TestNormalizeResolver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"8.8.8.8", "8.8.8.8:53"},
		{"8.8.8.8:53", "8.8.8.8:53"},
		{"2606:4700:4700::1111", "[2606:4700:4700::1111]:53"},
		{"[2606:4700:4700::1111]", "[2606:4700:4700::1111]:53"},
		{"[2606:4700:4700::1111]:53", "[2606:4700:4700::1111]:53"},
		{"dns.google", "dns.google:53"},
		{"dns.google:853", "dns.google:853"},
	}

	for _, tc := range tests {
		got := normalizeResolver(tc.input)
		if got != tc.expected {
			t.Errorf("normalizeResolver(%q) = %q; want %q", tc.input, got, tc.expected)
		}
	}
}

func TestReverseAddr_IPv4MappedIPv6(t *testing.T) {
	arpa, err := reverseAddr("::ffff:8.8.8.8")
	if err != nil {
		t.Fatalf("Unexpected error for ::ffff:8.8.8.8: %v", err)
	}
	expected := "8.8.8.8.in-addr.arpa."
	if arpa != expected {
		t.Errorf("reverseAddr(::ffff:8.8.8.8) = %q; want %q", arpa, expected)
	}
}

func TestRdnsHandler_PrivateIP_Forbidden(t *testing.T) {
	body := []byte(`{"ip": "10.0.0.1"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/rdns", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	RdnsHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected status 403 Forbidden for private target, got %d: %s", rec.Code, rec.Body.String())
	}
}
