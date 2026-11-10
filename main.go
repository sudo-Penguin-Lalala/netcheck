package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sudo-Penguin-Lalala/netcheck/internal/handlers"
	"github.com/sudo-Penguin-Lalala/netcheck/internal/middleware"
)

//go:embed all:frontend
var frontendFS embed.FS

type healthzResponse struct {
	Status       string `json:"status"`
	Version      string `json:"version"`
	AuthRequired bool   `json:"auth_required"`
}

func main() {
	subFS, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		log.Fatalf("frontend fs: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(healthzResponse{
			Status:       "ok",
			Version:      "2.0.0",
			AuthRequired: middleware.AuthRequired(),
		})
	})

	mux.HandleFunc("POST /api/ping", handlers.PingHandler)
	mux.HandleFunc("POST /api/traceroute", handlers.TracerouteHandler)
	mux.HandleFunc("POST /api/mtr", handlers.MtrHandler)
	mux.HandleFunc("POST /api/port", handlers.PortHandler)
	mux.HandleFunc("POST /api/ssl", handlers.SslHandler)
	mux.HandleFunc("POST /api/http", handlers.HttpHandler)
	mux.HandleFunc("POST /api/dns", handlers.DnsHandler)
	mux.HandleFunc("POST /api/rdns", handlers.RdnsHandler)
	mux.HandleFunc("POST /api/whois", handlers.WhoisHandler)
	mux.HandleFunc("GET /api/ip", handlers.ClientIPHandler)
	mux.HandleFunc("GET /api/ip-lookup", handlers.IPLookupHandler)
	mux.HandleFunc("GET /api/ip-lookup/{ip}", handlers.IPLookupHandler)

	mux.Handle("GET /", http.FileServerFS(subFS))

	corsCfg := middleware.NewCORSConfig()
	handler := middleware.CORS(corsCfg, middleware.SecurityHeaders(middleware.TokenAuth(middleware.RateLimit(mux))))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	addr := ":" + port

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("listening on %s", addr)
		serverErrors <- server.ListenAndServe()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server died: %v", err)
		}
	case sig := <-shutdown:
		log.Printf("shutting down on signal %v", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			_ = server.Close()
		}
	}
}
