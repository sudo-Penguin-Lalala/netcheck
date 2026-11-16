package handlers

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sudo-Penguin-Lalala/netcheck/internal/engine"
)

var tlsPorts = map[int]struct{}{
	443: {}, 465: {}, 563: {}, 636: {}, 989: {}, 990: {}, 992: {}, 993: {}, 994: {}, 995: {}, 8443: {}, 9443: {},
}

var interestingHeaders = map[string]struct{}{
	"content-type":              {},
	"content-length":            {},
	"server":                    {},
	"location":                  {},
	"cache-control":             {},
	"content-encoding":          {},
	"x-powered-by":              {},
	"strict-transport-security": {},
	"x-frame-options":           {},
	"x-content-type-options":    {},
	"set-cookie":                {},
	"cf-ray":                    {},
}

func PortHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		baseTargetRequest
		Port int `json:"port"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}

	target := req.getTarget()
	if err := checkTargetSecurity(r.Context(), target); err != nil {
		HandleError(w, err)
		return
	}

	if req.Port < 1 || req.Port > 65535 {
		JSONError(w, http.StatusBadRequest, "Port must be an integer between 1 and 65535")
		return
	}

	protocol := "HTTP"
	if _, ok := tlsPorts[req.Port]; ok {
		protocol = "HTTPS"
	}

	payload := map[string]any{
		"target": target,
		"type":   "http",
		"limit":  1,
		"measurementOptions": map[string]any{
			"port":     req.Port,
			"protocol": protocol,
			"request": map[string]string{
				"path":   "/",
				"method": "HEAD",
			},
		},
	}
	if locs := engine.BuildLocations(req.Location); locs != nil {
		payload["locations"] = locs
	}

	resBytes, err := engine.RunMeasurement(r.Context(), payload)
	if err != nil {
		HandleError(w, err)
		return
	}

	status := classifyPort(resBytes)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"host":   target,
		"port":   req.Port,
		"status": status,
	})
}

func classifyPort(bodyBytes []byte) string {
	var gpRes struct {
		Results []struct {
			Result struct {
				Timings struct {
					TCP any `json:"tcp"`
				} `json:"timings"`
				RawOutput string `json:"rawOutput"`
			} `json:"result"`
		} `json:"results"`
	}
	if err := json.Unmarshal(bodyBytes, &gpRes); err != nil || len(gpRes.Results) == 0 {
		return "closed"
	}

	res := gpRes.Results[0].Result
	if res.Timings.TCP != nil && toFloat(res.Timings.TCP) >= 0 {
		return "open"
	}

	raw := strings.ToLower(res.RawOutput)
	openSignals := []string{
		"other side closed", "socket hang up", "premature close",
		"econnreset", "epipe", "parse error", "invalid http",
		"does not match the http", "expected http/",
	}
	for _, sig := range openSignals {
		if strings.Contains(raw, sig) {
			return "open"
		}
	}

	if strings.Contains(raw, "etimedout") || strings.Contains(raw, "timed out") || strings.Contains(raw, "timeout") {
		return "timeout"
	}
	return "closed"
}

func SslHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		baseTargetRequest
		Port int `json:"port"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}

	target := req.getTarget()
	if err := checkTargetSecurity(r.Context(), target); err != nil {
		HandleError(w, err)
		return
	}

	port := req.Port
	if port == 0 {
		port = 443
	} else if port < 1 || port > 65535 {
		JSONError(w, http.StatusBadRequest, "Port must be an integer between 1 and 65535")
		return
	}

	payload := map[string]any{
		"target": target,
		"type":   "http",
		"limit":  1,
		"measurementOptions": map[string]any{
			"port":     port,
			"protocol": "HTTPS",
			"request": map[string]string{
				"path":   "/",
				"method": "HEAD",
			},
		},
	}
	if locs := engine.BuildLocations(req.Location); locs != nil {
		payload["locations"] = locs
	}

	resBytes, err := engine.RunMeasurement(r.Context(), payload)
	if err != nil {
		HandleError(w, err)
		return
	}

	var gpRes struct {
		Results []struct {
			Result struct {
				TLS *struct {
					CreatedAt *string `json:"createdAt"`
					ExpiresAt *string `json:"expiresAt"`
					Subject   struct {
						CN  string `json:"CN"`
						Alt string `json:"alt"`
					} `json:"subject"`
					Issuer struct {
						O  string `json:"O"`
						CN string `json:"CN"`
						OU string `json:"OU"`
					} `json:"issuer"`
				} `json:"tls"`
				RawOutput string `json:"rawOutput"`
			} `json:"result"`
		} `json:"results"`
	}
	if err := json.Unmarshal(resBytes, &gpRes); err != nil {
		JSONError(w, http.StatusBadGateway, "Invalid response from upstream probe")
		return
	}

	if len(gpRes.Results) == 0 || gpRes.Results[0].Result.TLS == nil {
		raw := ""
		if len(gpRes.Results) > 0 {
			raw = gpRes.Results[0].Result.RawOutput
		}
		msg := "TLS Handshake Failed: Port did not negotiate TLS or certificate chain rejected"
		if raw != "" {
			if len(raw) > 200 {
				raw = raw[:200]
			}
			msg = fmt.Sprintf("%s: %s", msg, raw)
		}
		JSONError(w, http.StatusBadGateway, msg)
		return
	}

	tlsData := gpRes.Results[0].Result.TLS
	var validFrom, validUntil string
	var daysRemaining int
	var expired bool

	if tlsData.CreatedAt != nil {
		validFrom = *tlsData.CreatedAt
	}
	if tlsData.ExpiresAt != nil {
		validUntil = *tlsData.ExpiresAt
		if t, err := time.Parse(time.RFC3339, *tlsData.ExpiresAt); err == nil {
			now := time.Now().UTC()
			diff := t.Sub(now).Hours() / 24
			if diff < float64(math.MaxInt) && diff > float64(math.MinInt) {
				daysRemaining = int(diff)
			}
			expired = t.Before(now)
		}
	}

	issuerOrg := tlsData.Issuer.O
	if issuerOrg == "" {
		issuerOrg = tlsData.Issuer.CN
	}
	if issuerOrg == "" {
		issuerOrg = tlsData.Issuer.OU
	}

	var sanList []string
	if tlsData.Subject.Alt != "" {
		for _, token := range strings.Split(tlsData.Subject.Alt, ",") {
			t := strings.TrimSpace(token)
			if strings.HasPrefix(t, "DNS:") {
				sanList = append(sanList, t[4:])
			} else if strings.HasPrefix(t, "IP Address:") {
				sanList = append(sanList, strings.TrimSpace(t[11:]))
			} else if t != "" {
				sanList = append(sanList, t)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"host": target,
		"port": port,
		"subject": map[string]string{
			"commonName": tlsData.Subject.CN,
		},
		"issuer": map[string]string{
			"organizationName": issuerOrg,
		},
		"valid_from":     validFrom,
		"valid_until":    validUntil,
		"days_remaining": daysRemaining,
		"expired":        expired,
		"san":            sanList,
	})
}

func HttpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		URL      string `json:"url"`
		Target   string `json:"target"`
		Location string `json:"location"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}

	targetURL := strings.TrimSpace(req.URL)
	if targetURL == "" {
		targetURL = strings.TrimSpace(req.Target)
	}
	if !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}

	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		JSONError(w, http.StatusBadRequest, "Malformed URL: Missing host component")
		return
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		JSONError(w, http.StatusBadRequest, "Unsupported protocol: Target URL must begin with http:// or https://")
		return
	}

	host := parsed.Hostname()
	if err := checkTargetSecurity(r.Context(), host); err != nil {
		HandleError(w, err)
		return
	}

	port := 80
	if scheme == "https" {
		port = 443
	}
	if parsed.Port() != "" {
		p, err := strconv.Atoi(parsed.Port())
		if err != nil || p < 1 || p > 65535 {
			JSONError(w, http.StatusBadRequest, "Invalid port: Port must be an integer between 1 and 65535")
			return
		}
		port = p
	}

	reqPath := parsed.Path
	if reqPath == "" {
		reqPath = "/"
	}
	if parsed.RawQuery != "" {
		reqPath = reqPath + "?" + parsed.RawQuery
	}

	proto := "HTTP"
	if scheme == "https" {
		proto = "HTTPS"
	}

	payload := map[string]any{
		"target": host,
		"type":   "http",
		"limit":  1,
		"measurementOptions": map[string]any{
			"port":     port,
			"protocol": proto,
			"request": map[string]string{
				"path":   reqPath,
				"method": "GET",
			},
		},
	}
	if locs := engine.BuildLocations(req.Location); locs != nil {
		payload["locations"] = locs
	}

	resBytes, err := engine.RunMeasurement(r.Context(), payload)
	if err != nil {
		HandleError(w, err)
		return
	}

	var gpRes struct {
		Results []struct {
			Result struct {
				StatusCode     any            `json:"statusCode"`
				StatusCodeName *string        `json:"statusCodeName"`
				Timings        map[string]any `json:"timings"`
				Headers        map[string]any `json:"headers"`
				TLS            *struct {
					Authorized *bool   `json:"authorized"`
					ExpiresAt  *string `json:"expiresAt"`
				} `json:"tls"`
			} `json:"result"`
		} `json:"results"`
	}
	if err := json.Unmarshal(resBytes, &gpRes); err != nil {
		JSONError(w, http.StatusBadGateway, "Invalid response from upstream probe")
		return
	}

	var statusCode *int
	statusText := ""
	var responseTimeMS *int
	filteredHeaders := make(map[string]string)
	var redirects []string

	if len(gpRes.Results) > 0 {
		res := gpRes.Results[0].Result
		if res.StatusCode != nil {
			sc := toInt(res.StatusCode)
			statusCode = &sc
		}
		if res.StatusCodeName != nil {
			statusText = *res.StatusCodeName
		}
		if res.Timings != nil && res.Timings["total"] != nil {
			tot := toFloat(res.Timings["total"])
			if tot < float64(math.MaxInt) && tot > float64(math.MinInt) {
				total := int(tot)
				responseTimeMS = &total
			}
		}

		for k, v := range res.Headers {
			if _, ok := interestingHeaders[strings.ToLower(k)]; ok {
				filteredHeaders[k] = fmt.Sprint(v)
			}
		}

		if statusCode != nil && *statusCode >= 300 && *statusCode < 400 {
			if loc, ok := filteredHeaders["location"]; ok && loc != "" {
				redirects = append(redirects, loc)
			} else if loc, ok := filteredHeaders["Location"]; ok && loc != "" {
				redirects = append(redirects, loc)
			}
		}
	}

	var tlsPayload any
	if len(gpRes.Results) > 0 && gpRes.Results[0].Result.TLS != nil {
		tlsBlock := gpRes.Results[0].Result.TLS
		var daysRemaining *int
		if tlsBlock.ExpiresAt != nil {
			if exp, err := time.Parse(time.RFC3339, *tlsBlock.ExpiresAt); err == nil {
				diff := exp.Sub(time.Now().UTC()).Hours() / 24
				if diff < float64(math.MaxInt) && diff > float64(math.MinInt) {
					days := int(diff)
					daysRemaining = &days
				}
			}
		}
		valid := false
		if tlsBlock.Authorized != nil {
			valid = *tlsBlock.Authorized
		}
		tlsPayload = map[string]any{
			"valid":          valid,
			"days_remaining": daysRemaining,
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"url":              targetURL,
		"status_code":      statusCode,
		"status_text":      statusText,
		"response_time_ms": responseTimeMS,
		"redirects":        redirects,
		"headers":          filteredHeaders,
		"tls":              tlsPayload,
	})
}
