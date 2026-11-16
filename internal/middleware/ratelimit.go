package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const maxRateLimitClients = 10000

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64
	mu       sync.Mutex
	interval time.Duration
	burst    int
}

type limiterStore struct {
	mu      sync.RWMutex
	clients map[string]*clientLimiter
	maxCap  int
}

var (
	globalLimiterStore = &limiterStore{
		clients: make(map[string]*clientLimiter),
		maxCap:  maxRateLimitClients,
	}
	cleanupOnce sync.Once
)

func init() {
	startRateLimitCleanup()
}

func startRateLimitCleanup() {
	cleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(2 * time.Minute)
			for range ticker.C {
				globalLimiterStore.cleanup(600)
			}
		}()
	})
}

func (s *limiterStore) cleanup(maxAgeSec int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for ip, cl := range s.clients {
		if now-cl.lastSeen.Load() > maxAgeSec {
			delete(s.clients, ip)
		}
	}
}

func (s *limiterStore) getOrCreate(ip string, interval time.Duration, burst int, now int64) *clientLimiter {
	s.mu.RLock()
	cl, exists := s.clients[ip]
	s.mu.RUnlock()

	if exists {
		cl.mu.Lock()
		if cl.interval != interval {
			cl.limiter.SetLimit(rate.Every(interval))
			cl.interval = interval
		}
		if cl.burst != burst {
			cl.limiter.SetBurst(burst)
			cl.burst = burst
		}
		cl.mu.Unlock()
		return cl
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	if cl, exists := s.clients[ip]; exists {
		cl.mu.Lock()
		if cl.interval != interval {
			cl.limiter.SetLimit(rate.Every(interval))
			cl.interval = interval
		}
		if cl.burst != burst {
			cl.limiter.SetBurst(burst)
			cl.burst = burst
		}
		cl.mu.Unlock()
		return cl
	}

	// If capacity reached, aggressively evict entries older than 3 minutes
	if len(s.clients) >= s.maxCap {
		for k, v := range s.clients {
			if now-v.lastSeen.Load() > 180 {
				delete(s.clients, k)
			}
		}
		// If still full, prune oldest lastSeen clients down to 80% capacity to prevent memory exhaustion
		if len(s.clients) >= s.maxCap {
			type clientEntry struct {
				ip       string
				lastSeen int64
			}
			entries := make([]clientEntry, 0, len(s.clients))
			for k, v := range s.clients {
				entries = append(entries, clientEntry{ip: k, lastSeen: v.lastSeen.Load()})
			}
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].lastSeen < entries[j].lastSeen
			})
			targetLen := s.maxCap * 4 / 5
			toDelete := len(s.clients) - targetLen
			for i := 0; i < toDelete && i < len(entries); i++ {
				delete(s.clients, entries[i].ip)
			}
		}
	}

	cl = &clientLimiter{
		limiter:  rate.NewLimiter(rate.Every(interval), burst),
		interval: interval,
		burst:    burst,
	}
	cl.lastSeen.Store(now)
	s.clients[ip] = cl
	return cl
}

func getRateLimitConfig() (rpm int, burst int, enabled bool) {
	rpmStr := strings.TrimSpace(os.Getenv("RATE_LIMIT_RPM"))
	burstStr := strings.TrimSpace(os.Getenv("RATE_LIMIT_BURST"))

	// Default: 60 req/min (1 req/sec), burst of 20
	rpm = 60
	burst = 20
	enabled = true

	if rpmStr == "0" || strings.EqualFold(rpmStr, "off") || strings.EqualFold(rpmStr, "false") ||
		strings.EqualFold(rpmStr, "none") || strings.EqualFold(rpmStr, "disabled") || rpmStr == "-1" {
		return 0, 0, false
	}

	if v, err := strconv.Atoi(rpmStr); err == nil && v > 0 {
		rpm = v
	}
	if v, err := strconv.Atoi(burstStr); err == nil && v > 0 {
		burst = v
	}
	return rpm, burst, true
}

// RateLimit enforces token-bucket rate limiting per client IP on /api/* endpoints.
// Configured via RATE_LIMIT_RPM (default: 60) and RATE_LIMIT_BURST (default: 20).
// Set RATE_LIMIT_RPM=0 to disable rate limiting completely (unlimited).
// Uses a bounded limiter store capped at 10,000 entries to prevent memory exhaustion DoS attacks.
func RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/api/healthz" || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		rpm, burst, enabled := getRateLimitConfig()
		if !enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := ExtractClientIP(r)
		now := time.Now().Unix()
		interval := time.Minute / time.Duration(rpm)

		cl := globalLimiterStore.getOrCreate(ip, interval, burst, now)
		cl.lastSeen.Store(now)

		if !cl.limiter.Allow() {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "rate_limited",
				"message": fmt.Sprintf("Rate Limit Exceeded (HTTP 429): Quota %d/minute exceeded. Back off before retrying.", rpm),
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
