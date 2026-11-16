package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func getTestHandler(t *testing.T) http.Handler {
	t.Helper()
	subFS, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		t.Fatalf("failed to sub frontendFS: %v", err)
	}

	handler, err := setupHandler(subFS)
	if err != nil {
		t.Fatalf("setupHandler failed: %v", err)
	}
	return handler
}

func TestEndToEnd_StaticAssetsAndSecurityHeaders(t *testing.T) {
	handler := getTestHandler(t)

	// 1. Root index.html
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("Expected text/html content-type for /, got %q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("Missing CSP header on static response")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("Expected X-Frame-Options: DENY, got %q", rec.Header().Get("X-Frame-Options"))
	}

	// 2. CSS Asset with caching headers
	reqCSS := httptest.NewRequest(http.MethodGet, "/style.css", nil)
	recCSS := httptest.NewRecorder()
	handler.ServeHTTP(recCSS, reqCSS)

	if recCSS.Code != http.StatusOK {
		t.Fatalf("GET /style.css expected 200, got %d", recCSS.Code)
	}
	if !strings.Contains(recCSS.Header().Get("Cache-Control"), "public, max-age=86400") {
		t.Errorf("Expected public caching header on CSS, got %q", recCSS.Header().Get("Cache-Control"))
	}

	// 3. Directory listing protection: trailing slash returns 404
	reqDirSlash := httptest.NewRequest(http.MethodGet, "/src/", nil)
	recDirSlash := httptest.NewRecorder()
	handler.ServeHTTP(recDirSlash, reqDirSlash)
	if recDirSlash.Code != http.StatusNotFound {
		t.Errorf("GET /src/ expected 404, got %d", recDirSlash.Code)
	}

	// 4. Directory existence leak protection: extensionless directory returns 404, not 301
	reqDirNoSlash := httptest.NewRequest(http.MethodGet, "/src", nil)
	recDirNoSlash := httptest.NewRecorder()
	handler.ServeHTTP(recDirNoSlash, reqDirNoSlash)
	if recDirNoSlash.Code != http.StatusNotFound {
		t.Errorf("GET /src expected 404, got %d", recDirNoSlash.Code)
	}
}

func TestEndToEnd_HealthCheck_BypassesAuthAndRateLimit(t *testing.T) {
	t.Setenv("AUTH_TOKEN", "test-secret-token")
	t.Setenv("RATE_LIMIT_BURST", "1")
	t.Setenv("RATE_LIMIT_RPM", "1")

	handler := getTestHandler(t)

	// Make 5 rapid calls to /api/healthz with NO auth token
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Health check request %d: Expected 200, got %d", i+1, rec.Code)
		}

		var data healthzResponse
		if err := json.NewDecoder(rec.Body).Decode(&data); err != nil {
			t.Fatalf("Failed to parse healthz response JSON: %v", err)
		}
		if data.Status != "ok" || data.Version != "2.0.3" || !data.AuthRequired {
			t.Errorf("Unexpected healthz data: %+v", data)
		}
	}
}

func TestEndToEnd_AuthProtectionPipeline(t *testing.T) {
	const secret = "correct-horse-battery-staple"
	t.Setenv("AUTH_TOKEN", secret)

	handler := getTestHandler(t)

	// 1. Unauthenticated request to protected endpoint -> 401
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/headers", nil)
	recUnauth := httptest.NewRecorder()
	handler.ServeHTTP(recUnauth, reqUnauth)

	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized without token, got %d", recUnauth.Code)
	}

	// 2. Invalid token -> 401
	reqBad := httptest.NewRequest(http.MethodGet, "/api/headers", nil)
	reqBad.Header.Set("Authorization", "Bearer wrong-token")
	recBad := httptest.NewRecorder()
	handler.ServeHTTP(recBad, reqBad)

	if recBad.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 with wrong token, got %d", recBad.Code)
	}

	// 3. Valid token in Authorization header -> 200
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/headers", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+secret)
	recAuth := httptest.NewRecorder()
	handler.ServeHTTP(recAuth, reqAuth)

	if recAuth.Code != http.StatusOK {
		t.Fatalf("Expected 200 with valid token, got %d", recAuth.Code)
	}
}

func TestEndToEnd_BodyLimitEnforcement(t *testing.T) {
	handler := getTestHandler(t)

	// Send oversized valid JSON payload (>1MB) to POST /api/ping
	oversizedBody := []byte(`{"host":"` + strings.Repeat("a", (1<<20)+1024) + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/ping", bytes.NewReader(oversizedBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Expected 413 Payload Too Large on >1MB body, got %d", rec.Code)
	}

	var errResp map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&errResp)
	if errResp["error"] != "payload_too_large" {
		t.Errorf("Expected error code 'payload_too_large', got %q", errResp["error"])
	}
}

func TestEndToEnd_RateLimitEnforcement(t *testing.T) {
	t.Setenv("RATE_LIMIT_BURST", "2")
	t.Setenv("RATE_LIMIT_RPM", "10")

	handler := getTestHandler(t)

	clientIP := "198.51.100.77:4321"

	// 2 requests should pass
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/headers", nil)
		req.RemoteAddr = clientIP
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Request %d: Expected 200, got %d", i+1, rec.Code)
		}
	}

	// 3rd request exceeds burst capacity -> 429
	reqOver := httptest.NewRequest(http.MethodGet, "/api/headers", nil)
	reqOver.RemoteAddr = clientIP
	recOver := httptest.NewRecorder()
	handler.ServeHTTP(recOver, reqOver)

	if recOver.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 429 Too Many Requests on burst exhaustion, got %d", recOver.Code)
	}
	if recOver.Header().Get("Retry-After") != "60" {
		t.Errorf("Expected Retry-After: 60 header on 429 response")
	}
}

func TestCheckHealth_CLI(t *testing.T) {
	handler := getTestHandler(t)
	server := httptest.NewServer(handler)
	defer server.Close()

	parts := strings.Split(server.Listener.Addr().String(), ":")
	port := parts[len(parts)-1]

	// 1. Success on active server
	if err := checkHealth(port); err != nil {
		t.Fatalf("checkHealth expected success, got error: %v", err)
	}

	// 2. Failure on non-existent port
	if err := checkHealth("59999"); err == nil {
		t.Errorf("checkHealth on inactive port expected failure, got nil")
	}
}

func TestGracefulShutdown_DrainInFlight(t *testing.T) {
	inFlightStarted := make(chan struct{})
	inFlightDone := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		close(inFlightStarted)
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("drained"))
		close(inFlightDone)
	})

	server := &http.Server{
		Handler: mux,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	go func() {
		_ = server.Serve(listener)
	}()

	// Start slow in-flight request
	reqDone := make(chan int, 1)
	go func() {
		resp, err := http.Get("http://" + listener.Addr().String() + "/slow")
		if err != nil {
			reqDone <- -1
			return
		}
		defer resp.Body.Close()
		reqDone <- resp.StatusCode
	}()

	// Wait until handler is actively processing
	<-inFlightStarted

	// Trigger graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Server.Shutdown failed: %v", err)
	}

	// Verify in-flight request completed successfully
	select {
	case code := <-reqDone:
		if code != http.StatusOK {
			t.Errorf("Expected in-flight request to finish with 200, got %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("In-flight request timed out during graceful shutdown")
	}

	<-inFlightDone
}
