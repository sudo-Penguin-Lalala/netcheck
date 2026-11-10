package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestGlobalpingRunMeasurement_Success(t *testing.T) {
	var pollCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodPost && r.URL.Path == "/measurements" {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "test-mid-123"})
			return
		}

		if r.Method == http.MethodGet && r.URL.Path == "/measurements/test-mid-123" {
			if atomic.AddInt32(&pollCount, 1) < 3 {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":     "test-mid-123",
					"status": "in-progress",
				})
				return
			}

			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":     "test-mid-123",
				"status": "finished",
				"results": []map[string]any{
					{
						"result": map[string]any{
							"rawOutput": "PING 1.1.1.1 56 data bytes",
						},
					},
				},
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	_ = os.Setenv("GLOBALPING_API", server.URL)
	_ = os.Setenv("ALLOW_PRIVATE_TARGETS", "1")
	defer os.Unsetenv("GLOBALPING_API")
	defer os.Unsetenv("ALLOW_PRIVATE_TARGETS")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload := map[string]any{
		"target": "1.1.1.1",
		"type":   "ping",
	}

	resBytes, err := RunMeasurement(ctx, payload)
	if err != nil {
		t.Fatalf("RunMeasurement failed: %v", err)
	}

	var res map[string]any
	if err := json.Unmarshal(resBytes, &res); err != nil {
		t.Fatalf("Failed to parse returned JSON: %v", err)
	}

	if res["status"] != "finished" {
		t.Errorf("Expected status 'finished', got %v", res["status"])
	}

	if atomic.LoadInt32(&pollCount) < 3 {
		t.Errorf("Expected at least 3 polls, got %d", atomic.LoadInt32(&pollCount))
	}
}
