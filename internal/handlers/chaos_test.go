package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sudo-Penguin-Lalala/netcheck/internal/middleware"
)

func setupMockGlobalping(t *testing.T) func() {
	mockGP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "chaos-test-id"})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "finished",
			"results": []map[string]any{
				{
					"result": map[string]any{
						"stats":     map[string]any{"total": 10, "rcv": 10, "loss": 0},
						"rawOutput": "chaos test output",
					},
				},
			},
		})
	}))

	prevAPI := os.Getenv("GLOBALPING_API")
	_ = os.Setenv("GLOBALPING_API", mockGP.URL)

	return func() {
		mockGP.Close()
		if prevAPI != "" {
			_ = os.Setenv("GLOBALPING_API", prevAPI)
		} else {
			_ = os.Unsetenv("GLOBALPING_API")
		}
	}
}

// Chaos Test 1: Bizarre, Malformed, and Pathological JSON Payloads
func TestChaos_MalformedJSONPayloads(t *testing.T) {
	cleanup := setupMockGlobalping(t)
	defer cleanup()

	whoisCache.Add("chaos-mock-target.com", WhoisResult{Raw: "mocked"})
	defer whoisCache.Remove("chaos-mock-target.com")

	endpoints := []struct {
		name    string
		handler http.HandlerFunc
		url     string
	}{
		{"Ping", PingHandler, "/api/ping"},
		{"Traceroute", TracerouteHandler, "/api/traceroute"},
		{"MTR", MtrHandler, "/api/mtr"},
		{"Port", PortHandler, "/api/port"},
		{"SSL", SslHandler, "/api/ssl"},
		{"HTTP", HttpHandler, "/api/http"},
		{"DNS", DnsHandler, "/api/dns"},
		{"rDNS", RdnsHandler, "/api/rdns"},
		{"WHOIS", WhoisHandler, "/api/whois"},
	}

	chaoticBodies := []struct {
		name string
		raw  string
	}{
		{"EmptyBody", ""},
		{"WhitespaceOnly", "   \t\r\n   "},
		{"StringLiteral", `"just a string"`},
		{"IntegerLiteral", `12345`},
		{"BooleanLiteral", `true`},
		{"NullLiteral", `null`},
		{"ArrayLiteral", `[1, 2, 3]`},
		{"EmptyObject", `{}`},
		{"UnterminatedObject", `{"target": "google.com"`},
		{"BrokenSyntax", `{target: "test"}`},
		{"NullByteInKey", `{"\u0000target": "google.com"}`},
		{"NullByteInValue", `{"target": "google.com\u0000evil.com"}`},
		{"ExtremeNesting", strings.Repeat(`{"a":`, 50) + `1` + strings.Repeat(`}`, 50)},
		{"TypeMismatch_TargetIsArray", `{"target": ["google.com"]}`},
		{"TypeMismatch_TargetIsInt", `{"target": 123456}`},
		{"TypeMismatch_PortIsString", `{"target": "google.com", "port": "eighty"}`},
		{"TypeMismatch_PortIsBool", `{"target": "google.com", "port": true}`},
		{"HugeGarbageField", `{"target": "google.com", "junk": "` + strings.Repeat("A", 16384) + `"}`},
	}

	for _, ep := range endpoints {
		for _, cb := range chaoticBodies {
			t.Run(ep.name+"_"+cb.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodPost, ep.url, bytes.NewReader([]byte(cb.raw)))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()

				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("PANIC on %s with payload %s: %v", ep.name, cb.name, r)
					}
				}()

				ep.handler(rec, req)

				if rec.Code == http.StatusInternalServerError {
					t.Errorf("HTTP 500 Internal Server Error returned on %s with %s: %s", ep.name, cb.name, rec.Body.String())
				}
			})
		}
	}
}

// Chaos Test 2: Wild, Weird & Edge-Case Hostname / Target Inputs
func TestChaos_WildTargetInputs(t *testing.T) {
	cleanup := setupMockGlobalping(t)
	defer cleanup()

	wildTargets := []string{
		"",
		" ",
		"   google.com   ",
		"google..com",
		"..",
		"...",
		".",
		"http://google.com",
		"https://google.com/path?query=1#hash",
		"ftp://google.com",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"//google.com",
		"://",
		":///",
		"google.com:443",
		"1.1.1.1:80",
		"[::1]:443",
		"example.com; rm -rf /",
		"example.com && ping 8.8.8.8",
		"example.com | cat /etc/passwd",
		"example.com`id`",
		"example.com$(id)",
		strings.Repeat("a", 254) + ".com",
		strings.Repeat("a", 300) + ".com",
		"label-with-trailing-hyphen-.com",
		"-label-with-leading-hyphen.com",
		"0177.0.0.1",
		"0x7f.0.0.1",
		"2130706433",
		"127.1",
		"::ffff:127.0.0.1",
		"64:ff9b::127.0.0.1",
		"2002:7f00:0001::",
		"169.254.169.254",
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
		"224.0.0.1", // Multicast
		"240.0.0.1", // Class E
		"255.255.255.255",
		"0.0.0.0",
	}

	for _, target := range wildTargets {
		t.Run("Target_"+target, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"target": target, "port": 80})
			req := httptest.NewRequest(http.MethodPost, "/api/port", bytes.NewReader(body))
			rec := httptest.NewRecorder()

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC on target %q: %v", target, r)
				}
			}()

			PortHandler(rec, req)

			if rec.Code == http.StatusInternalServerError {
				t.Errorf("Target %q caused HTTP 500: %s", target, rec.Body.String())
			}
		})
	}
}

// Chaos Test 3: Port Boundary Torture on /api/port
func TestChaos_PortBoundaryTorture(t *testing.T) {
	cleanup := setupMockGlobalping(t)
	defer cleanup()

	wildPorts := []int{
		-65536,
		-1,
		0,
		1,
		80,
		443,
		65535,
		65536,
		70000,
		100000,
		2147483647,
		-2147483648,
	}

	for _, port := range wildPorts {
		t.Run(fmt.Sprintf("Port_%d", port), func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"target": "1.1.1.1", "port": port})
			req := httptest.NewRequest(http.MethodPost, "/api/port", bytes.NewReader(body))
			rec := httptest.NewRecorder()

			PortHandler(rec, req)

			if port < 1 || port > 65535 {
				if rec.Code != http.StatusBadRequest {
					t.Errorf("PortHandler: Expected 400 for out-of-range port %d, got %d", port, rec.Code)
				}
			}
		})
	}
}

// Chaos Test 4: Chaotic DNS Inputs (Crazy types, server names, ports)
func TestChaos_DNSResolverTorture(t *testing.T) {
	chaoticServers := []struct {
		server       string
		expectStatus int
	}{
		{"", 0},
		{"   ", 0},
		{":53", http.StatusBadRequest},
		{"1.1.1.1:abc", http.StatusBadRequest},
		{"1.1.1.1:65536", http.StatusBadRequest},
		{"1.1.1.1:0", http.StatusBadRequest},
		{"1.1.1.1:-53", http.StatusBadRequest},
		{"999.999.999.999:53", http.StatusBadRequest},
		{"not-a-valid-hostname-at-all!!!:53", http.StatusBadRequest},
		{"127.0.0.1:53", http.StatusForbidden},
		{"127.0.0.53:53", http.StatusForbidden},
		{"169.254.169.254:53", http.StatusForbidden},
		{"10.255.255.255:53", http.StatusForbidden},
		{"[::1]:53", http.StatusForbidden},
		{"::1", http.StatusForbidden},
		{"[fe80::1]:53", http.StatusForbidden},
		{"64:ff9b::127.0.0.1:53", http.StatusForbidden},
		{"[64:ff9b::127.0.0.1]:53", http.StatusForbidden},
	}

	for _, cs := range chaoticServers {
		t.Run("DNS_Server_"+cs.server, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{
				"host":   "one.one.one.one",
				"type":   "A",
				"server": cs.server,
			})
			req := httptest.NewRequest(http.MethodPost, "/api/dns", bytes.NewReader(body))
			rec := httptest.NewRecorder()

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC on server %q: %v", cs.server, r)
				}
			}()

			DnsHandler(rec, req)

			if cs.expectStatus != 0 && rec.Code != cs.expectStatus {
				t.Errorf("Server %q: Expected status %d, got %d (%s)", cs.server, cs.expectStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

// Chaos Test 5: IP Lookup Parameter Pollution & Malformed Formats
func TestChaos_IPLookupFuzzing(t *testing.T) {
	weirdIPs := []string{
		"",
		"   ",
		"256.1.1.1",
		"1.2.3.4.5",
		"999.999.999.999",
		"::g",
		"2001:::1",
		"1.1.1.1%eth0",
		"1.1.1.1\r\nX-Injected: true",
		"1.1.1.1<script>alert(1)</script>",
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.1",
		"::1",
		"0.0.0.0",
		"255.255.255.255",
	}

	for _, ip := range weirdIPs {
		t.Run("IP_"+ip, func(t *testing.T) {
			targetURL := "/api/ip-lookup?ip=" + url.QueryEscape(ip)
			req := httptest.NewRequest(http.MethodGet, targetURL, nil)
			rec := httptest.NewRecorder()

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC on IP %q: %v", ip, r)
				}
			}()

			IPLookupHandler(rec, req)

			if rec.Code == http.StatusInternalServerError {
				t.Errorf("IPLookupHandler returned HTTP 500 for %q: %s", ip, rec.Body.String())
			}
		})
	}
}

// Chaos Test 6: Body Limit Torture (Sending huge payloads)
func TestChaos_BodyLimitBomb(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/ping", PingHandler)
	handler := middleware.BodyLimit(1 << 20)(mux) // 1MB limit

	// Create a payload > 1MB (1.5MB of garbage JSON)
	hugePayload := []byte(`{"target": "` + strings.Repeat("a", 1500000) + `"}`)

	req := httptest.NewRequest(http.MethodPost, "/api/ping", bytes.NewReader(hugePayload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIC on BodyLimitBomb: %v", r)
		}
	}()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected 413 Payload Too Large, got %d", rec.Code)
	}
}

// Chaos Test 7: Rate Limiter Map Exhaustion & LRU Bounding
func TestChaos_RateLimitExhaustion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := middleware.RateLimit(mux)

	// Simulate 2000 different IPs firing 1 request each
	for i := 0; i < 2000; i++ {
		ip := fmt.Sprintf("198.51.%d.%d", (i/256)%256, i%256)
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.RemoteAddr = ip + ":12345"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("RateLimiter failed on distinct IP %s: %d", ip, rec.Code)
		}
	}
}

// Chaos Test 8: Bearer Token Auth Torture (Huge tokens, timing side-channels)
func TestChaos_TokenAuthTorture(t *testing.T) {
	_ = os.Setenv("AUTH_TOKEN", "super-secret-secure-token-12345")
	defer os.Unsetenv("AUTH_TOKEN")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := middleware.TokenAuth(mux)

	// Test variations of token lengths and formats
	testTokens := []string{
		"",
		"s",
		"super",
		"super-secret-secure-token-12344", // 1 char diff at end
		"super-secret-secure-token-12345", // Exact match
		"super-secret-secure-token-123456", // 1 char longer
		strings.Repeat("X", 100000),       // 100KB giant token
	}

	for _, tok := range testTokens {
		req := httptest.NewRequest(http.MethodGet, "/api/secret", nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if tok == "super-secret-secure-token-12345" {
			if rec.Code != http.StatusOK {
				t.Errorf("Expected 200 for exact token, got %d", rec.Code)
			}
		} else {
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("Expected 401 for token %q, got %d", tok, rec.Code)
			}
		}
	}
}

// Chaos Test 9: High-Concurrency Slamming (100 Goroutines firing at once)
func TestChaos_HighConcurrencySlamming(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("POST /api/ping", PingHandler)
	mux.HandleFunc("GET /api/ip", ClientIPHandler)

	handler := middleware.SecurityHeaders(middleware.BodyLimit(1 << 20)(middleware.RateLimit(mux)))

	var wg sync.WaitGroup
	concurrentRequests := 100

	start := make(chan struct{})

	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start // Wait for all goroutines to sync before firing simultaneously

			clientIP := fmt.Sprintf("198.51.100.%d", id%10)

			// 1. Healthz
			reqH := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
			reqH.RemoteAddr = clientIP + ":54321"
			recH := httptest.NewRecorder()
			handler.ServeHTTP(recH, reqH)
			if recH.Code != http.StatusOK {
				t.Errorf("Healthz failed under load: %d", recH.Code)
			}

			// 2. Client IP
			reqIP := httptest.NewRequest(http.MethodGet, "/api/ip", nil)
			reqIP.RemoteAddr = clientIP + ":54321"
			reqIP.Header.Set("Accept", "text/plain")
			recIP := httptest.NewRecorder()
			handler.ServeHTTP(recIP, reqIP)

			// 3. Ping with private block
			body := []byte(`{"target": "127.0.0.1"}`)
			reqP := httptest.NewRequest(http.MethodPost, "/api/ping", bytes.NewReader(body))
			reqP.RemoteAddr = clientIP + ":54321"
			recP := httptest.NewRecorder()
			handler.ServeHTTP(recP, reqP)

			if recP.Code != http.StatusForbidden && recP.Code != http.StatusTooManyRequests {
				t.Errorf("Expected 403 or 429 under load, got %d", recP.Code)
			}
		}(i)
	}

	close(start)
	wg.Wait()
}

// Chaos Test 10: Premature Client Disconnection (Context Cancellation)
func TestChaos_PrematureClientDisconnection(t *testing.T) {
	whoisTarget := "chaos-disconnect-target.com"
	whoisCache.Add(whoisTarget, WhoisResult{Raw: "mocked"})
	defer whoisCache.Remove(whoisTarget)

	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(time.Duration(i*50) * time.Microsecond)
			cancel()
		}()

		req := httptest.NewRequest(http.MethodPost, "/api/whois", bytes.NewReader([]byte(`{"target":"`+whoisTarget+`"}`)))
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()

		done := make(chan struct{})
		go func() {
			WhoisHandler(rec, req)
			close(done)
		}()

		select {
		case <-done:
			// Handled gracefully
		case <-time.After(2 * time.Second):
			t.Fatal("Deadlock or hanging goroutine on client disconnect")
		}
	}
}
