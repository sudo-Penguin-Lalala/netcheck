package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultAPIBase = "https://api.globalping.io/v1"
	pollTimeout    = 35 * time.Second
)

var (
	initialPollIntervals = []time.Duration{
		200 * time.Millisecond,
		300 * time.Millisecond,
		500 * time.Millisecond,
		750 * time.Millisecond,
	}
	defaultPollInterval = 1000 * time.Millisecond

	validLocations = map[string]struct{}{
		"WORLD": {},
		"NA":    {},
		"EU":    {},
		"AS":    {},
		"SA":    {},
		"AF":    {},
		"OC":    {},
	}
)

type GlobalpingError struct {
	StatusCode int    `json:"status"`
	Code       string `json:"error"`
	Message    string `json:"message"`
}

func (e *GlobalpingError) Error() string {
	return fmt.Sprintf("[%d %s] %s", e.StatusCode, e.Code, e.Message)
}

type Location struct {
	Magic string `json:"magic"`
}

func NormalizeLocation(loc string) string {
	upper := strings.ToUpper(strings.TrimSpace(loc))
	if _, ok := validLocations[upper]; ok && upper != "WORLD" {
		return upper
	}
	return "world"
}

// nil location lets Globalping route to the nearest probes automatically
func BuildLocations(loc string) []Location {
	code := NormalizeLocation(loc)
	if code == "world" {
		return nil
	}
	return []Location{{Magic: code}}
}

func getAPIBase() string {
	if api := strings.TrimSpace(os.Getenv("GLOBALPING_API")); api != "" {
		return strings.TrimRight(api, "/")
	}
	return defaultAPIBase
}

func getGlobalpingToken() string {
	return strings.TrimSpace(os.Getenv("GLOBALPING_TOKEN"))
}

func applyGlobalpingHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	if token := getGlobalpingToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func SubmitMeasurement(ctx context.Context, payload any) (string, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	url := getAPIBase() + "/measurements"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	applyGlobalpingHeaders(req)

	resp, err := GetHTTPClient().Do(req)
	if err != nil {
		return "", &GlobalpingError{
			StatusCode: http.StatusBadGateway,
			Code:       "upstream_failure",
			Message:    fmt.Sprintf("Globalping connection failed: %v", err),
		}
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", &GlobalpingError{
			StatusCode: http.StatusBadGateway,
			Code:       "upstream_failure",
			Message:    "Failed to read Globalping response body",
		}
	}

	if resp.StatusCode == http.StatusAccepted {
		var submitRes struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(respBytes, &submitRes); err != nil || submitRes.ID == "" {
			return "", &GlobalpingError{
				StatusCode: http.StatusBadGateway,
				Code:       "upstream_failure",
				Message:    "Globalping accepted but returned invalid measurement ID",
			}
		}
		return submitRes.ID, nil
	}

	if resp.StatusCode == http.StatusUnprocessableEntity {
		msg := "Invalid target or measurement options"
		var errObj struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(respBytes, &errObj); err == nil && errObj.Error.Message != "" {
			msg = errObj.Error.Message
		}
		return "", &GlobalpingError{
			StatusCode: http.StatusBadRequest,
			Code:       "bad_input",
			Message:    msg,
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", &GlobalpingError{
			StatusCode: http.StatusTooManyRequests,
			Code:       "upstream_rate_limited",
			Message:    "Globalping rate limit reached; try again later",
		}
	}

	return "", &GlobalpingError{
		StatusCode: http.StatusBadGateway,
		Code:       "upstream_failure",
		Message:    fmt.Sprintf("Globalping error (HTTP %d)", resp.StatusCode),
	}
}

func PollMeasurement(ctx context.Context, mid string) ([]byte, error) {
	url := fmt.Sprintf("%s/measurements/%s", getAPIBase(), mid)
	client := GetHTTPClient()

	deadline := time.Now().Add(pollTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	pollCount := 0

	for {
		if time.Now().After(deadline) {
			return nil, &GlobalpingError{
				StatusCode: http.StatusGatewayTimeout,
				Code:       "timeout",
				Message:    "Globalping measurement did not finish in time",
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("create poll request: %w", err)
		}
		applyGlobalpingHeaders(req)

		resp, err := client.Do(req)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(getInterval(pollCount)):
				pollCount++
				continue
			}
		}

		respBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		if readErr != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(getInterval(pollCount)):
				pollCount++
				continue
			}
		}

		if resp.StatusCode != http.StatusOK {
			return nil, &GlobalpingError{
				StatusCode: http.StatusBadGateway,
				Code:       "upstream_failure",
				Message:    fmt.Sprintf("Poll returned HTTP %d", resp.StatusCode),
			}
		}

		var statusObj struct {
			Status  string `json:"status"`
			Results []struct {
				Result struct {
					RawOutput string `json:"rawOutput"`
				} `json:"result"`
			} `json:"results"`
		}

		if err := json.Unmarshal(respBytes, &statusObj); err == nil {
			switch statusObj.Status {
			case "finished":
				return respBytes, nil
			case "failed", "offline", "error":
				msg := fmt.Sprintf("Globalping measurement %s", statusObj.Status)
				if len(statusObj.Results) > 0 && statusObj.Results[0].Result.RawOutput != "" {
					raw := statusObj.Results[0].Result.RawOutput
					if len(raw) > 150 {
						raw = raw[:150]
					}
					msg = fmt.Sprintf("%s: %s", msg, raw)
				}
				return nil, &GlobalpingError{
					StatusCode: http.StatusBadGateway,
					Code:       "upstream_failure",
					Message:    msg,
				}
			}
		}

		interval := getInterval(pollCount)
		pollCount++

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func getInterval(count int) time.Duration {
	if count < len(initialPollIntervals) {
		return initialPollIntervals[count]
	}
	return defaultPollInterval
}

func RunMeasurement(ctx context.Context, payload any) ([]byte, error) {
	mid, err := SubmitMeasurement(ctx, payload)
	if err != nil {
		return nil, err
	}
	return PollMeasurement(ctx, mid)
}
