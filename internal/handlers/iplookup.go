package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/sudo-Penguin-Lalala/netcheck/internal/engine"
	"github.com/sudo-Penguin-Lalala/netcheck/internal/middleware"
)

func extractClientIP(r *http.Request) string {
	return middleware.ExtractClientIP(r)
}

var dropRequestHeaders = map[string]struct{}{
	"host":                {},
	"connection":          {},
	"content-length":      {},
	"authorization":       {},
	"cookie":              {},
	"proxy-authorization": {},
	"x-api-key":           {},
	"x-auth-token":        {},
	"x-csrf-token":        {},
	"x-xsrf-token":        {},
}

func HeadersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	headers := make(map[string]string)
	for name, values := range r.Header {
		key := strings.ToLower(name)
		if _, drop := dropRequestHeaders[key]; drop {
			continue
		}
		headers[key] = strings.Join(values, ", ")
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"headers": headers,
	})
}

func ClientIPHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := extractClientIP(r)

	acceptJSON := strings.Contains(r.Header.Get("Accept"), "application/json")
	isTextRequest := strings.Contains(r.Header.Get("Accept"), "text/plain") ||
		r.URL.Query().Get("format") == "text" ||
		r.URL.Query().Get("format") == "plain" ||
		strings.HasPrefix(r.UserAgent(), "curl/")

	if isTextRequest && !acceptJSON {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(clientIP + "\n"))
		return
	}

	info := fetchIPInfo(r.Context(), clientIP)
	if len(info) == 0 {
		JSONError(w, http.StatusBadGateway, "All IP lookup upstreams failed to respond")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(info)
}

const maxIPInfoBytes = 1024 * 1024 // 1 MB cap

func fetchIPInfo(ctx context.Context, clientIP string) map[string]any {
	client := engine.GetHTTPClient()
	apiKey := strings.TrimSpace(os.Getenv("IPWHOIS_API_KEY"))

	if addr, err := netip.ParseAddr(clientIP); err == nil {
		clientIP = addr.WithZone("").Unmap().String()
	}

	urlPrimary := fmt.Sprintf("https://ipwho.is/%s", clientIP)
	if apiKey != "" {
		urlPrimary = fmt.Sprintf("https://ipwhois.pro/%s?key=%s", clientIP, apiKey)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlPrimary, nil)
	if err == nil {
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var data map[string]any
				if err := json.NewDecoder(io.LimitReader(resp.Body, maxIPInfoBytes)).Decode(&data); err == nil {
					if success, ok := data["success"].(bool); ok && success {
						conn, _ := data["connection"].(map[string]any)
						tz, _ := data["timezone"].(map[string]any)

						return map[string]any{
							"ip":        data["ip"],
							"success":   true,
							"type":      data["type"],
							"continent": data["continent"],
							"country":   data["country"],
							"region":    data["region"],
							"city":      data["city"],
							"latitude":  data["latitude"],
							"longitude": data["longitude"],
							"is_eu":     data["is_eu"],
							"asn":       conn["asn"],
							"org":       conn["org"],
							"isp":       conn["isp"],
							"timezone":  tz["id"],
							"utc":       tz["utc"],
						}
					}
				}
			}
		}
	}

	fallbackURL := fmt.Sprintf("https://ipapi.co/%s/json/", clientIP)
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, fallbackURL, nil)
	if err == nil {
		req2.Header.Set("User-Agent", "NetCheck/2.0.3")
		resp, err := client.Do(req2)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var data struct {
					Error       bool    `json:"error"`
					IP          string  `json:"ip"`
					CountryName string  `json:"country_name"`
					Region      string  `json:"region"`
					City        string  `json:"city"`
					Latitude    float64 `json:"latitude"`
					Longitude   float64 `json:"longitude"`
					Timezone    string  `json:"timezone"`
					Org         string  `json:"org"`
					ASN         string  `json:"asn"`
				}
				if err := json.NewDecoder(io.LimitReader(resp.Body, maxIPInfoBytes)).Decode(&data); err == nil && !data.Error && data.IP != "" {
					var asnVal any
					if strings.HasPrefix(data.ASN, "AS") {
						if num, err := strconv.Atoi(strings.TrimPrefix(data.ASN, "AS")); err == nil {
							asnVal = num
						}
					}
					ipType := "IPv4"
					if strings.Contains(clientIP, ":") {
						ipType = "IPv6"
					}

					return map[string]any{
						"ip":        data.IP,
						"success":   true,
						"type":      ipType,
						"continent": "",
						"country":   data.CountryName,
						"region":    data.Region,
						"city":      data.City,
						"latitude":  data.Latitude,
						"longitude": data.Longitude,
						"is_eu":     false,
						"asn":       asnVal,
						"org":       data.Org,
						"isp":       data.Org,
						"timezone":  data.Timezone,
						"utc":       "",
					}
				}
			}
		}
	}

	return nil
}

func IPLookupHandler(w http.ResponseWriter, r *http.Request) {
	ipStr := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ipStr == "" {
		ipStr = strings.TrimSpace(r.PathValue("ip"))
	}

	if ipStr == "" {
		JSONError(w, http.StatusBadRequest, "Missing IP address parameter")
		return
	}

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "Invalid IP address: Must be a valid IPv4 or IPv6 format")
		return
	}

	cleanAddr := addr.WithZone("").Unmap()
	if engine.IsRestrictedIP(cleanAddr) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "forbidden",
			"message": "RFC 1918 Forbidden: Geolocation and ASN lookups are not supported for private/loopback IPs",
		})
		return
	}

	cleanIP := cleanAddr.String()
	client := engine.GetHTTPClient()
	apiKey := strings.TrimSpace(os.Getenv("IPWHOIS_API_KEY"))

	urlPrimary := fmt.Sprintf("https://ipwho.is/%s", cleanIP)
	if apiKey != "" {
		urlPrimary = fmt.Sprintf("https://ipwhois.pro/%s?key=%s", cleanIP, apiKey)
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, urlPrimary, nil)
	if err == nil {
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var data map[string]any
				if err := json.NewDecoder(io.LimitReader(resp.Body, maxIPInfoBytes)).Decode(&data); err == nil {
					if success, ok := data["success"].(bool); ok && success {
						conn, _ := data["connection"].(map[string]any)
						tz, _ := data["timezone"].(map[string]any)

						w.Header().Set("Content-Type", "application/json; charset=utf-8")
						_ = json.NewEncoder(w).Encode(map[string]any{
							"ip":        data["ip"],
							"success":   true,
							"type":      data["type"],
							"continent": data["continent"],
							"country":   data["country"],
							"region":    data["region"],
							"city":      data["city"],
							"latitude":  data["latitude"],
							"longitude": data["longitude"],
							"is_eu":     data["is_eu"],
							"asn":       conn["asn"],
							"org":       conn["org"],
							"isp":       conn["isp"],
							"timezone":  tz["id"],
							"utc":       tz["utc"],
						})
						return
					}
				}
			}
		}
	}

	fallbackURL := fmt.Sprintf("https://ipapi.co/%s/json/", cleanIP)
	req2, err := http.NewRequestWithContext(r.Context(), http.MethodGet, fallbackURL, nil)
	if err == nil {
		req2.Header.Set("User-Agent", "NetCheck/2.0.3")
		resp, err := client.Do(req2)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var data struct {
					Error       bool    `json:"error"`
					IP          string  `json:"ip"`
					CountryName string  `json:"country_name"`
					Region      string  `json:"region"`
					City        string  `json:"city"`
					Latitude    float64 `json:"latitude"`
					Longitude   float64 `json:"longitude"`
					Timezone    string  `json:"timezone"`
					Org         string  `json:"org"`
					ASN         string  `json:"asn"`
				}
				if err := json.NewDecoder(io.LimitReader(resp.Body, maxIPInfoBytes)).Decode(&data); err == nil && !data.Error && data.IP != "" {
					var asnVal any
					if strings.HasPrefix(data.ASN, "AS") {
						if num, err := strconv.Atoi(strings.TrimPrefix(data.ASN, "AS")); err == nil {
							asnVal = num
						}
					}
					ipType := "IPv4"
					if strings.Contains(ipStr, ":") {
						ipType = "IPv6"
					}

					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"ip":        data.IP,
						"success":   true,
						"type":      ipType,
						"continent": "",
						"country":   data.CountryName,
						"region":    data.Region,
						"city":      data.City,
						"latitude":  data.Latitude,
						"longitude": data.Longitude,
						"is_eu":     false,
						"asn":       asnVal,
						"org":       data.Org,
						"isp":       data.Org,
						"timezone":  data.Timezone,
						"utc":       "",
					})
					return
				}
			}
		}
	}

	JSONError(w, http.StatusBadGateway, "All IP lookup upstreams failed to respond or returned invalid data")
}
