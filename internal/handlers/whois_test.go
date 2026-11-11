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
