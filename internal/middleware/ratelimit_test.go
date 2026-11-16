package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestRateLimit_BoundedMemoryCap(t *testing.T) {
	// Create a test store with small maxCap (e.g. 50)
	store := &limiterStore{
		clients: make(map[string]*clientLimiter),
		maxCap:  50,
	}

	now := time.Now().Unix()
	// Bombard store with 200 unique IP addresses
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		store.getOrCreate(ip, time.Minute, 10, now)
	}

	store.mu.RLock()
	count := len(store.clients)
	store.mu.RUnlock()

	if count > 50 {
		t.Fatalf("Memory leak: Expected at most 50 clients in store, got %d", count)
	}
}

func TestRateLimit_Cleanup(t *testing.T) {
	store := &limiterStore{
		clients: make(map[string]*clientLimiter),
		maxCap:  100,
	}

	now := time.Now().Unix()
	// Add 3 old clients (>600s ago) and 2 fresh clients
	c1 := store.getOrCreate("192.0.2.1", time.Minute, 10, now-700)
	c1.lastSeen.Store(now - 700)
	c2 := store.getOrCreate("192.0.2.2", time.Minute, 10, now-650)
	c2.lastSeen.Store(now - 650)
	c3 := store.getOrCreate("192.0.2.3", time.Minute, 10, now)
	_ = c3

	store.cleanup(600)

	store.mu.RLock()
	defer store.mu.RUnlock()

	if _, exists := store.clients["192.0.2.1"]; exists {
		t.Errorf("Expected 192.0.2.1 to be cleaned up")
	}
	if _, exists := store.clients["192.0.2.2"]; exists {
		t.Errorf("Expected 192.0.2.2 to be cleaned up")
	}
	if _, exists := store.clients["192.0.2.3"]; !exists {
		t.Errorf("Expected fresh client 192.0.2.3 to be preserved")
	}
}

func TestRateLimit_MalformedEnvFallback(t *testing.T) {
	t.Setenv("RATE_LIMIT_RPM", "invalid-number")
	t.Setenv("RATE_LIMIT_BURST", "not-an-int")

	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RateLimit(dummy)

	req := httptest.NewRequest(http.MethodPost, "/api/ping", nil)
	req.RemoteAddr = "192.0.2.50:5000"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should not crash and should succeed under fallback default
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 with fallback defaults on malformed env, got %d", rec.Code)
	}
}
