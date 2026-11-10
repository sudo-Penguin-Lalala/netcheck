package middleware

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

func AuthRequired() bool {
	return strings.TrimSpace(os.Getenv("AUTH_TOKEN")) != ""
}

func TokenAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(os.Getenv("AUTH_TOKEN"))
		if token == "" || r.URL.Path == "/api/healthz" || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "unauthorized",
				"message": "Missing or invalid Authorization header",
			})
			return
		}

		provided := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "unauthorized",
				"message": "Invalid token",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
