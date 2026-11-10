package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64
}

var clients sync.Map

func init() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			now := time.Now().Unix()
			clients.Range(func(key, value any) bool {
				if cl, ok := value.(*clientLimiter); ok {
					if now-cl.lastSeen.Load() > 600 {
						clients.Delete(key)
					}
				}
				return true
			})
		}
	}()
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
		val, ok := clients.Load(ip)
		var cl *clientLimiter
		if ok {
			cl = val.(*clientLimiter)
			cl.limiter.SetLimit(rate.Every(interval))
			cl.limiter.SetBurst(burst)
		} else {
			newCl := &clientLimiter{limiter: rate.NewLimiter(rate.Every(interval), burst)}
			newCl.lastSeen.Store(now)
			actual, loaded := clients.LoadOrStore(ip, newCl)
			if loaded {
				cl = actual.(*clientLimiter)
				cl.limiter.SetLimit(rate.Every(interval))
				cl.limiter.SetBurst(burst)
			} else {
				cl = newCl
			}
		}

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
