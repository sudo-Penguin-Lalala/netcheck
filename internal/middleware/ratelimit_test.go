package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimit_AllowsUnderBurst(t *testing.T) {
	t.Setenv("RATE_LIMIT_BURST", "5")
	t.Setenv("RATE_LIMIT_RPM", "10")

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := RateLimit(dummy)

	// Burst capacity is 5, so 5 immediate requests should all succeed
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/ping", nil)
		req.RemoteAddr = "198.51.100.10:12345"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Request %d: Expected 200, got %d", i+1, rec.Code)
		}
	}

	// 6th request immediately exceeds burst limit
	req := httptest.NewRequest(http.MethodPost, "/api/ping", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 429 Too Many Requests on 6th burst request, got %d", rec.Code)
	}

	if rec.Header().Get("Retry-After") != "60" {
		t.Errorf("Expected Retry-After header '60', got %q", rec.Header().Get("Retry-After"))
	}
}

func TestRateLimit_Disabled_NoLimit(t *testing.T) {
	t.Setenv("RATE_LIMIT_RPM", "0")

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := RateLimit(dummy)

	// When disabled with RATE_LIMIT_RPM=0, 50 consecutive requests must all succeed
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/ping", nil)
		req.RemoteAddr = "198.51.100.99:12345"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Request %d: Expected 200 with rate limiting disabled, got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimit_BypassesStaticAndHealth(t *testing.T) {
	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := RateLimit(dummy)

	// 10 rapid requests to /api/healthz should never be rate limited
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
		req.RemoteAddr = "198.51.100.20:12345"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Health check request %d: Expected 200, got %d", i+1, rec.Code)
		}
	}

	// 10 rapid requests to static files should never be rate limited
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
		req.RemoteAddr = "198.51.100.20:12345"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Static file request %d: Expected 200, got %d", i+1, rec.Code)
		}
	}
}
