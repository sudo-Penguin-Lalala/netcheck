package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestJSONErrorFormat(t *testing.T) {
	rec := httptest.NewRecorder()
	JSONError(rec, http.StatusBadRequest, "Invalid parameter")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400, got %d", rec.Code)
	}

	var res map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("Failed to parse JSON error: %v", err)
	}

	if res["error"] != "bad_input" {
		t.Errorf("Expected error 'bad_input', got %q", res["error"])
	}
	if res["message"] != "Invalid parameter" {
		t.Errorf("Expected message 'Invalid parameter', got %q", res["message"])
	}
}

func TestPingHandler_BlocksPrivate(t *testing.T) {
	_ = os.Unsetenv("ALLOW_PRIVATE_TARGETS")

	body := []byte(`{"host": "127.0.0.1", "count": 4}`)
	req := httptest.NewRequest(http.MethodPost, "/api/ping", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	PingHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 Forbidden for loopback ping, got %d", rec.Code)
	}
}

func TestPortHandler_Validations(t *testing.T) {
	_ = os.Unsetenv("ALLOW_PRIVATE_TARGETS")

	// 1. Invalid Port
	body := []byte(`{"host": "1.1.1.1", "port": 70000}`)
	req := httptest.NewRequest(http.MethodPost, "/api/port", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	PortHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for port > 65535, got %d", rec.Code)
	}

	// 2. Private host blocked
	body = []byte(`{"host": "192.168.1.1", "port": 80}`)
	req = httptest.NewRequest(http.MethodPost, "/api/port", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	PortHandler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for private target, got %d", rec.Code)
	}
}

func TestIPLookupHandler_RejectsPrivate(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/ip-lookup?ip=10.0.0.1", nil)
	rec := httptest.NewRecorder()

	IPLookupHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request for private IP lookup, got %d", rec.Code)
	}

	var res map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res["error"] != "forbidden" {
		t.Errorf("Expected error code 'forbidden', got %q", res["error"])
	}
}

func TestExtractClientIP_TrustedProxies(t *testing.T) {
	// Request coming from loopback (trusted proxy default 127.0.0.1)
	req := httptest.NewRequest(http.MethodGet, "/api/ip", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("CF-Connecting-IP", "203.0.113.195")

	clientIP := extractClientIP(req)
	if clientIP != "203.0.113.195" {
		t.Errorf("Expected extracted IP 203.0.113.195, got %q", clientIP)
	}

	// Request coming from untrusted remote address
	reqUntrusted := httptest.NewRequest(http.MethodGet, "/api/ip", nil)
	reqUntrusted.RemoteAddr = "198.51.100.5:12345"
	reqUntrusted.Header.Set("CF-Connecting-IP", "203.0.113.195")

	clientIP = extractClientIP(reqUntrusted)
	if clientIP != "198.51.100.5" {
		t.Errorf("Expected untrusted client IP 198.51.100.5, got %q", clientIP)
	}
}

func TestHeadersHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/headers", nil)
	req.Header.Set("User-Agent", "NetCheck-Tester/2.0")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "session=secret-cookie")
	req.Header.Set("X-Custom-Header", "Hello-NetCheck")

	rec := httptest.NewRecorder()
	HeadersHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", rec.Code)
	}

	var res struct {
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if res.Headers["user-agent"] != "NetCheck-Tester/2.0" {
		t.Errorf("Expected user-agent header preserved, got %q", res.Headers["user-agent"])
	}
	if res.Headers["x-custom-header"] != "Hello-NetCheck" {
		t.Errorf("Expected x-custom-header preserved, got %q", res.Headers["x-custom-header"])
	}

	// Sensitive headers must be dropped
	if _, ok := res.Headers["authorization"]; ok {
		t.Errorf("Authorization header should have been dropped")
	}
	if _, ok := res.Headers["cookie"]; ok {
		t.Errorf("Cookie header should have been dropped")
	}

	// POST method not allowed
	postReq := httptest.NewRequest(http.MethodPost, "/api/headers", nil)
	postRec := httptest.NewRecorder()
	HeadersHandler(postRec, postReq)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 Method Not Allowed, got %d", postRec.Code)
	}
}
