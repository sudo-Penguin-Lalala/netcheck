package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWhoisHandler_LiveOrCached(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live network test in -short mode")
	}
	body := []byte(`{"target": "cloudflare.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/whois", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	WhoisHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var res WhoisResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("Failed to decode WHOIS response: %v", err)
	}

	if len(res.Nameservers) == 0 && res.Registrar == nil {
		t.Errorf("Expected populated registrar or nameservers, got %+v", res)
	}

	// Second request should hit LRU cache instantaneously
	req2 := httptest.NewRequest(http.MethodPost, "/api/whois", bytes.NewReader(body))
	rec2 := httptest.NewRecorder()
	WhoisHandler(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for cached WHOIS, got %d", rec2.Code)
	}
}

func TestWhois_NameserversNotNull(t *testing.T) {
	parsed := parseWhoisNameservers("no nameservers here")
	if parsed == nil {
		t.Fatal("parseWhoisNameservers should return non-nil empty slice")
	}

	res := WhoisResult{
		Nameservers: parsed,
	}
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("Failed to marshal WhoisResult: %v", err)
	}
	if bytes.Contains(data, []byte(`"nameservers":null`)) {
		t.Errorf("Expected 'nameservers:[]', got null in JSON: %s", string(data))
	}
}

func TestWhois_RejectSingleLabelAndIP(t *testing.T) {
	for _, target := range []string{"payroll-internal", "db-master", "1.1.1.1", "127.0.0.1"} {
		body, _ := json.Marshal(map[string]string{"target": target})
		req := httptest.NewRequest(http.MethodPost, "/api/whois", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		WhoisHandler(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected 400 for target %q, got %d: %s", target, rec.Code, rec.Body.String())
		}
	}
}
