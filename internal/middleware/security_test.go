package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := SecurityHeaders(dummy)

	tests := []struct {
		path               string
		expectedCacheCtrl  string
		checkCSP           bool
	}{
		{
			path:              "/api/ping",
			expectedCacheCtrl: "no-store, no-cache, must-revalidate",
			checkCSP:          true,
		},
		{
			path:              "/app.js",
			expectedCacheCtrl: "public, max-age=86400, stale-while-revalidate=3600",
			checkCSP:          true,
		},
		{
			path:              "/style.css",
			expectedCacheCtrl: "public, max-age=86400, stale-while-revalidate=3600",
			checkCSP:          true,
		},
		{
			path:              "/font.woff2",
			expectedCacheCtrl: "public, max-age=86400, stale-while-revalidate=3600",
			checkCSP:          true,
		},
		{
			path:              "/",
			expectedCacheCtrl: "no-cache, must-revalidate",
			checkCSP:          true,
		},
		{
			path:              "/index.html",
			expectedCacheCtrl: "no-cache, must-revalidate",
			checkCSP:          true,
		},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Path %s: Expected 200, got %d", tc.path, rec.Code)
		}

		if got := rec.Header().Get("Cache-Control"); got != tc.expectedCacheCtrl {
			t.Errorf("Path %s: Cache-Control got %q, want %q", tc.path, got, tc.expectedCacheCtrl)
		}

		if tc.checkCSP {
			if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
				t.Errorf("Path %s: Missing or invalid CSP: %q", tc.path, csp)
			}
			if nosniff := rec.Header().Get("X-Content-Type-Options"); nosniff != "nosniff" {
				t.Errorf("Path %s: X-Content-Type-Options got %q, want nosniff", tc.path, nosniff)
			}
			if frame := rec.Header().Get("X-Frame-Options"); frame != "DENY" {
				t.Errorf("Path %s: X-Frame-Options got %q, want DENY", tc.path, frame)
			}
			if ref := rec.Header().Get("Referrer-Policy"); ref != "no-referrer" {
				t.Errorf("Path %s: Referrer-Policy got %q, want no-referrer", tc.path, ref)
			}
			if perm := rec.Header().Get("Permissions-Policy"); perm != PermissionsPolicy {
				t.Errorf("Path %s: Permissions-Policy got %q, want %q", tc.path, perm, PermissionsPolicy)
			}
		}
	}
}

func TestBodyLimit_UnderLimit(t *testing.T) {
	const limit = 1024 // 1 KB
	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	handler := BodyLimit(limit)(dummy)

	payload := []byte(strings.Repeat("A", 500)) // 500 bytes < 1024
	req := httptest.NewRequest(http.MethodPost, "/api/test", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != string(payload) {
		t.Errorf("Body mismatch under limit")
	}
}

func TestBodyLimit_ExceedsLimit(t *testing.T) {
	const limit = 1024 // 1 KB
	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				http.Error(w, "payload_too_large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := BodyLimit(limit)(dummy)

	payload := []byte(strings.Repeat("A", 2048)) // 2 KB > 1024
	req := httptest.NewRequest(http.MethodPost, "/api/test", bytes.NewReader(payload))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Expected 413 Payload Too Large, got %d", rec.Code)
	}
}

func TestCORS_DisabledByDefault(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "")
	cfg := NewCORSConfig()
	if cfg != nil {
		t.Fatalf("Expected nil CORSConfig when ALLOWED_ORIGINS is unset")
	}

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CORS(cfg, dummy)
	req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Expected no CORS header when disabled, got %q", got)
	}
}

func TestCORS_AllowAll(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "*")
	cfg := NewCORSConfig()
	if cfg == nil || !cfg.AllowAll {
		t.Fatalf("Expected AllowAll true when ALLOWED_ORIGINS=*")
	}

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CORS(cfg, dummy)

	// Regular request with Origin
	req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	req.Header.Set("Origin", "https://random-site.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("Expected '*', got %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}

	// Preflight OPTIONS request
	optReq := httptest.NewRequest(http.MethodOptions, "/api/ping", nil)
	optReq.Header.Set("Origin", "https://random-site.com")
	optRec := httptest.NewRecorder()
	handler.ServeHTTP(optRec, optReq)

	if optRec.Code != http.StatusNoContent {
		t.Errorf("Expected 204 No Content for preflight, got %d", optRec.Code)
	}
	if optRec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("Expected '*' on preflight, got %q", optRec.Header().Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(optRec.Header().Get("Access-Control-Allow-Methods"), "POST") {
		t.Errorf("Missing expected allow methods in preflight")
	}
}

func TestCORS_WhitelistedOrigins(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "https://app.example.com, https://test.io:8443, malformed-url")
	cfg := NewCORSConfig()
	if cfg == nil {
		t.Fatalf("Expected non-nil CORSConfig")
	}
	if cfg.AllowAll {
		t.Errorf("AllowAll should be false for specific whitelist")
	}

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CORS(cfg, dummy)

	// 1. Whitelisted origin
	req1 := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	req1.Header.Set("Origin", "https://app.example.com")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("Expected allow-origin for whitelisted origin, got %q", rec1.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec1.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("Expected Access-Control-Allow-Credentials: true")
	}
	if rec1.Header().Get("Vary") != "Origin" {
		t.Errorf("Expected Vary: Origin")
	}

	// 2. Whitelisted origin with port
	req2 := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	req2.Header.Set("Origin", "https://test.io:8443")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Header().Get("Access-Control-Allow-Origin") != "https://test.io:8443" {
		t.Errorf("Expected allow-origin for origin with port, got %q", rec2.Header().Get("Access-Control-Allow-Origin"))
	}

	// 3. Untrusted origin
	req3 := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	req3.Header.Set("Origin", "https://evil.attacker.com")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	if rec3.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("Expected NO allow-origin for untrusted origin, got %q", rec3.Header().Get("Access-Control-Allow-Origin"))
	}

	// 4. Preflight for whitelisted origin
	optReq := httptest.NewRequest(http.MethodOptions, "/api/ping", nil)
	optReq.Header.Set("Origin", "https://app.example.com")
	optRec := httptest.NewRecorder()
	handler.ServeHTTP(optRec, optReq)

	if optRec.Code != http.StatusNoContent {
		t.Errorf("Expected 204 for allowed preflight, got %d", optRec.Code)
	}

	// 5. Preflight for disallowed origin -> passes through to dummy handler (200), no CORS headers
	optReqBad := httptest.NewRequest(http.MethodOptions, "/api/ping", nil)
	optReqBad.Header.Set("Origin", "https://evil.com")
	optRecBad := httptest.NewRecorder()
	handler.ServeHTTP(optRecBad, optReqBad)

	if optRecBad.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("Disallowed preflight should not set CORS header")
	}
}

func TestTokenAuth(t *testing.T) {
	t.Setenv("AUTH_TOKEN", "super-secret-production-token-12345")

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := TokenAuth(dummy)

	// 1. Missing header -> 401
	req1 := httptest.NewRequest(http.MethodPost, "/api/dns", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for missing header, got %d", rec1.Code)
	}

	// 2. Wrong token -> 401
	req2 := httptest.NewRequest(http.MethodPost, "/api/dns", nil)
	req2.Header.Set("Authorization", "Bearer wrong-token")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for wrong token, got %d", rec2.Code)
	}

	// 3. Valid token with "Bearer " -> 200
	req3 := httptest.NewRequest(http.MethodPost, "/api/dns", nil)
	req3.Header.Set("Authorization", "Bearer super-secret-production-token-12345")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Errorf("Expected 200 for valid token, got %d", rec3.Code)
	}

	// 4. Valid token with lowercase "bearer " (RFC 7235 case insensitive) -> 200
	req4 := httptest.NewRequest(http.MethodPost, "/api/dns", nil)
	req4.Header.Set("Authorization", "bearer super-secret-production-token-12345")
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusOK {
		t.Errorf("Expected 200 for lowercase bearer token, got %d", rec4.Code)
	}

	// 5. Bypass for /api/healthz without token -> 200
	req5 := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	rec5 := httptest.NewRecorder()
	handler.ServeHTTP(rec5, req5)
	if rec5.Code != http.StatusOK {
		t.Errorf("Expected 200 for healthz bypass, got %d", rec5.Code)
	}
}
