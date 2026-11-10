package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDnsHandler_A_Record(t *testing.T) {
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
