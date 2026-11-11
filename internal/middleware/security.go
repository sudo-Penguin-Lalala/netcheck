package middleware

import (
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const (
	ContentSecurityPolicy = "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"font-src 'self'; " +
		"img-src 'self' data:; " +
		"connect-src 'self' https://ipv4.icanhazip.com https://ipv6.icanhazip.com https://api4.ipify.org https://api6.ipify.org; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'"

	PermissionsPolicy = "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
)

var originRegex = regexp.MustCompile(`^https?://[a-zA-Z0-9.-]+(:[0-9]+)?$`)

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", PermissionsPolicy)

		path := r.URL.Path
		switch {
		case strings.HasPrefix(path, "/api/"):
			h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
		case strings.HasSuffix(path, ".css"),
			strings.HasSuffix(path, ".js"),
			strings.HasSuffix(path, ".svg"),
			strings.HasSuffix(path, ".png"),
			strings.HasSuffix(path, ".woff2"),
			strings.HasSuffix(path, ".ttf"):
			h.Set("Cache-Control", "public, max-age=86400, stale-while-revalidate=3600")
		case path == "/" || path == "/index.html":
			h.Set("Cache-Control", "no-cache, must-revalidate")
		}

		next.ServeHTTP(w, r)
	})
}

// BodyLimit limits the maximum size of incoming request bodies to prevent memory exhaustion DoS.
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

type CORSConfig struct {
	AllowAll bool
	Origins  map[string]struct{}
}

func NewCORSConfig() *CORSConfig {
	raw := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS"))
	if raw == "" {
		return nil
	}

	if raw == "*" {
		log.Println("SECURITY WARNING: ALLOWED_ORIGINS=* permits any website to access this API. Set specific origins in production.")
		return &CORSConfig{AllowAll: true}
	}

	origins := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		origin := strings.TrimSpace(item)
		if origin == "" {
			continue
		}
		if originRegex.MatchString(origin) {
			origins[origin] = struct{}{}
		} else {
			log.Printf("ignoring malformed CORS origin: %s", origin)
		}
	}

	if len(origins) == 0 {
		return nil
	}
	return &CORSConfig{Origins: origins}
}

func CORS(cfg *CORSConfig, next http.Handler) http.Handler {
	if cfg == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		allowed := false
		if cfg.AllowAll {
			allowed = true
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else if _, ok := cfg.Origins[origin]; ok {
			allowed = true
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
