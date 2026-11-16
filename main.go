package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

func checkHealth(port string) error {
	if port == "" {
		port = "7070"
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	url := fmt.Sprintf("http://127.0.0.1:%s/api/healthz", port)
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("probe failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("non-200 status: %d", resp.StatusCode)
	}

	var data healthzResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || data.Status != "ok" {
		return fmt.Errorf("invalid response payload: %q", data.Status)
	}

	return nil
}

func runHealthCheck() {
	port := os.Getenv("PORT")
	if err := checkHealth(port); err != nil {
		log.Printf("Health check failed: %v", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func setupHandler(fsys fs.FS) (http.Handler, error) {
	mux := http.NewServeMux()

	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(healthzResponse{
			Status:       "ok",
			Version:      "2.0.3",
			AuthRequired: middleware.AuthRequired(),
		})
	}
	mux.HandleFunc("GET /healthz", healthHandler)
	mux.HandleFunc("GET /api/healthz", healthHandler)

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
	mux.HandleFunc("GET /api/headers", handlers.HeadersHandler)

	if fsys != nil {
		fileServer := http.FileServerFS(fsys)
		mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				clean := strings.TrimPrefix(r.URL.Path, "/")
				if strings.HasSuffix(r.URL.Path, "/") {
					http.NotFound(w, r)
					return
				}
				if info, err := fs.Stat(fsys, clean); err == nil && info.IsDir() {
					http.NotFound(w, r)
					return
				}
			}
			fileServer.ServeHTTP(w, r)
		})
	}

	corsCfg := middleware.NewCORSConfig()
	handler := middleware.CORS(corsCfg, middleware.SecurityHeaders(middleware.BodyLimit(1<<20)(middleware.TokenAuth(middleware.RateLimit(mux)))))
	return handler, nil
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-healthcheck" || os.Args[1] == "--healthcheck") {
		runHealthCheck()
		return
	}

	log.SetOutput(os.Stdout)
	log.Println("Starting NetCheck v2.0.3")

	subFS, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		log.Fatalf("frontend fs: %v", err)
	}

	handler, err := setupHandler(subFS)
	if err != nil {
		log.Fatalf("setup handler: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "7070"
	}
	addr := ":" + port

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second, // Triệt tiêu Slowloris attack ở socket layer
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("Listening on :%s", port)
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
		log.Printf("Received signal %v, starting graceful shutdown...", sig)
		shutdownTimeout := 15 * time.Second
		if val := os.Getenv("SHUTDOWN_TIMEOUT"); val != "" {
			if d, err := time.ParseDuration(val); err == nil {
				shutdownTimeout = d
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Graceful shutdown timeout exceeded, forcing socket close: %v", err)
			_ = server.Close()
		} else {
			log.Println("Server gracefully stopped with all in-flight connections completed")
		}
	}
}
