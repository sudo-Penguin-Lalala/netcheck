package middleware

import (
	"encoding/json"
	"net/http"
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

// 10 req/min per IP, burst of 5
func RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/healthz" || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		ip := ExtractClientIP(r)
		now := time.Now().Unix()

		val, ok := clients.Load(ip)
		var cl *clientLimiter
		if ok {
			cl = val.(*clientLimiter)
		} else {
			newCl := &clientLimiter{limiter: rate.NewLimiter(rate.Every(6*time.Second), 5)}
			newCl.lastSeen.Store(now)
			actual, loaded := clients.LoadOrStore(ip, newCl)
			if loaded {
				cl = actual.(*clientLimiter)
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
				"message": "Rate Limit Exceeded (HTTP 429): Quota 10/minute exceeded. Back off before retrying.",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
