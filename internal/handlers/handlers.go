package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sudo-Penguin-Lalala/netcheck/internal/engine"
	"github.com/sudo-Penguin-Lalala/netcheck/internal/middleware"
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

var statusToCode = map[int]string{
	http.StatusBadRequest:            "bad_input",
	http.StatusUnauthorized:          "unauthorized",
	http.StatusForbidden:             "forbidden",
	http.StatusNotFound:              "not_found",
	http.StatusRequestEntityTooLarge: "payload_too_large",
	http.StatusTooManyRequests:       "rate_limited",
	http.StatusInternalServerError:   "internal_error",
	http.StatusBadGateway:            "upstream_failure",
	http.StatusGatewayTimeout:        "timeout",
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			JSONError(w, http.StatusRequestEntityTooLarge, "Request body exceeds allowed size limit")
			return false
		}
		JSONError(w, http.StatusBadRequest, "Invalid JSON request body")
		return false
	}
	return true
}

func JSONError(w http.ResponseWriter, status int, msg string) {
	code, ok := statusToCode[status]
	if !ok {
		code = "error"
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": msg,
	})
}

func HandleError(w http.ResponseWriter, err error) {
	var gpErr *engine.GlobalpingError
	if errors.As(err, &gpErr) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(gpErr.StatusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   gpErr.Code,
			"message": gpErr.Message,
		})
		return
	}

	if errors.Is(err, engine.ErrRestrictedIP) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "private_blocked",
			"message": "RFC 1918 Forbidden: Remote probes cannot route to private or loopback targets.",
		})
		return
	}

	JSONError(w, http.StatusBadGateway, err.Error())
}

func isValidHostname(host string) bool {
	host = strings.TrimSpace(host)
	if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) == 0 {
		return false
	}

	// RFC 1123: TLD cannot be all-numeric (prevents 0177.0.0.1 or 2130706433 from masquerading as hostnames)
	lastLabel := labels[len(labels)-1]
	isAllNumeric := true
	for _, ch := range lastLabel {
		if ch < '0' || ch > '9' {
			isAllNumeric = false
			break
		}
	}
	if isAllNumeric {
		return false
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return false
			}
		}
	}
	return true
}

func isValidHostOrIP(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, ok := engine.ParseLooseIPv4(s); ok {
		return true
	}
	return isValidHostname(s)
}

func checkTargetSecurity(ctx context.Context, target string) error {
	if !isValidHostOrIP(target) {
		return errors.New("Invalid target: Must be a valid IPv4, IPv6, or FQDN")
	}

	if engine.AllowPrivateTargets() {
		return nil
	}

	if ip, err := netip.ParseAddr(target); err == nil {
		if engine.IsRestrictedIP(ip) {
			return engine.ErrRestrictedIP
		}
		return nil
	}

	if ip, ok := engine.ParseLooseIPv4(target); ok {
		if engine.IsRestrictedIP(ip) {
			return engine.ErrRestrictedIP
		}
		return nil
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, target)
	if err != nil {
		return nil
	}

	for _, ipAddr := range ips {
		addr, ok := netip.AddrFromSlice(ipAddr.IP)
		if ok && engine.IsRestrictedIP(addr) {
			return engine.ErrRestrictedIP
		}
	}
	return nil
}

type baseTargetRequest struct {
	Host     string `json:"host"`
	Target   string `json:"target"`
	Location string `json:"location"`
}

func (b *baseTargetRequest) getTarget() string {
	t := strings.TrimSpace(b.Host)
	if t == "" {
		t = strings.TrimSpace(b.Target)
	}
	return strings.ToLower(t)
}

func PingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		baseTargetRequest
		Count int `json:"count"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}

	target := req.getTarget()
	if err := checkTargetSecurity(r.Context(), target); err != nil {
		HandleError(w, err)
		return
	}

	count := req.Count
	if count <= 0 {
		count = 10
	} else if count > 10 {
		count = 10
	}

	payload := map[string]any{
		"target": target,
		"type":   "ping",
		"limit":  1,
		"measurementOptions": map[string]any{
			"packets": count,
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
				Stats struct {
					Total any `json:"total"`
					Rcv   any `json:"rcv"`
					Loss  any `json:"loss"`
					Min   any `json:"min"`
					Avg   any `json:"avg"`
					Max   any `json:"max"`
				} `json:"stats"`
				RawOutput string `json:"rawOutput"`
			} `json:"result"`
		} `json:"results"`
	}
	_ = json.Unmarshal(resBytes, &gpRes)

	sent := 0
	recv := 0
	lossPct := 100.0
	minRTT, avgRTT, maxRTT := 0.0, 0.0, 0.0
	raw := "no probe results"

	if len(gpRes.Results) > 0 {
		res := gpRes.Results[0].Result
		raw = strings.TrimSpace(res.RawOutput)
		sent = toInt(res.Stats.Total)
		recv = toInt(res.Stats.Rcv)
		if res.Stats.Loss != nil {
			lossPct = toFloat(res.Stats.Loss)
		} else if sent > 0 {
			lossPct = float64(sent-recv) / float64(sent) * 100.0
		}
		minRTT = toFloat(res.Stats.Min)
		avgRTT = toFloat(res.Stats.Avg)
		maxRTT = toFloat(res.Stats.Max)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"host":         target,
		"packets_sent": sent,
		"packets_recv": recv,
		"loss_pct":     lossPct,
		"min":          minRTT,
		"avg":          avgRTT,
		"max":          maxRTT,
		"raw":          raw,
	})
}

func TracerouteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		baseTargetRequest
		MaxHops int `json:"max_hops"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}

	target := req.getTarget()
	if err := checkTargetSecurity(r.Context(), target); err != nil {
		HandleError(w, err)
		return
	}

	payload := map[string]any{
		"target": target,
		"type":   "traceroute",
		"limit":  1,
		"measurementOptions": map[string]any{
			"protocol": "ICMP",
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
				Hops []struct {
					ResolvedAddress  *string `json:"resolvedAddress"`
					ResolvedHostname *string `json:"resolvedHostname"`
					Timings          []struct {
						RTT any `json:"rtt"`
					} `json:"timings"`
				} `json:"hops"`
			} `json:"result"`
		} `json:"results"`
	}
	_ = json.Unmarshal(resBytes, &gpRes)

	type HopOut struct {
		N         int      `json:"n"`
		IP        *string  `json:"ip"`
		Hostname  *string  `json:"hostname"`
		LatencyMS *float64 `json:"latency_ms"`
	}

	var hops []HopOut
	if len(gpRes.Results) > 0 {
		for i, h := range gpRes.Results[0].Result.Hops {
			var bestRTT *float64
			for _, t := range h.Timings {
				if t.RTT != nil {
					v := toFloat(t.RTT)
					if bestRTT == nil || v < *bestRTT {
						bestRTT = &v
					}
				}
			}
			hostname := h.ResolvedHostname
			if hostname != nil && h.ResolvedAddress != nil && *hostname == *h.ResolvedAddress {
				hostname = nil
			}
			hops = append(hops, HopOut{
				N:         i + 1,
				IP:        h.ResolvedAddress,
				Hostname:  hostname,
				LatencyMS: bestRTT,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"hops": hops})
}

func MtrHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req baseTargetRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}

	target := req.getTarget()
	if err := checkTargetSecurity(r.Context(), target); err != nil {
		HandleError(w, err)
		return
	}

	payload := map[string]any{
		"target": target,
		"type":   "mtr",
		"limit":  1,
		"measurementOptions": map[string]any{
			"protocol": "ICMP",
			"packets":  10,
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
				Hops []struct {
					ResolvedAddress  *string `json:"resolvedAddress"`
					ResolvedHostname *string `json:"resolvedHostname"`
					Stats            struct {
						Total any `json:"total"`
						Rcv   any `json:"rcv"`
						Loss  any `json:"loss"`
						Min   any `json:"min"`
						Avg   any `json:"avg"`
						Max   any `json:"max"`
					} `json:"stats"`
				} `json:"hops"`
			} `json:"result"`
		} `json:"results"`
	}
	_ = json.Unmarshal(resBytes, &gpRes)

	type MtrHopOut struct {
		N        int      `json:"n"`
		IP       *string  `json:"ip"`
		Hostname *string  `json:"hostname"`
		LossPct  float64  `json:"loss_pct"`
		AvgMS    *float64 `json:"avg_ms"`
		BestMS   *float64 `json:"best_ms"`
		WorstMS  *float64 `json:"worst_ms"`
	}

	var hops []MtrHopOut
	if len(gpRes.Results) > 0 {
		for i, h := range gpRes.Results[0].Result.Hops {
			sent := toInt(h.Stats.Total)
			recv := toInt(h.Stats.Rcv)
			loss := 0.0
			if h.Stats.Loss != nil {
				loss = toFloat(h.Stats.Loss)
			} else if sent > 0 {
				loss = float64(sent-recv) / float64(sent) * 100.0
			}

			var avg, best, worst *float64
			if h.Stats.Avg != nil {
				v := toFloat(h.Stats.Avg)
				avg = &v
			}
			if h.Stats.Min != nil {
				v := toFloat(h.Stats.Min)
				best = &v
			}
			if h.Stats.Max != nil {
				v := toFloat(h.Stats.Max)
				worst = &v
			}

			hostname := h.ResolvedHostname
			if hostname != nil && h.ResolvedAddress != nil && *hostname == *h.ResolvedAddress {
				hostname = nil
			}

			hops = append(hops, MtrHopOut{
				N:        i + 1,
				IP:       h.ResolvedAddress,
				Hostname: hostname,
				LossPct:  loss,
				AvgMS:    avg,
				BestMS:   best,
				WorstMS:  worst,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"host": target,
		"hops": hops,
	})
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
	if port <= 0 {
		port = 443
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
	_ = json.Unmarshal(resBytes, &gpRes)

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
		if p, err := strconv.Atoi(parsed.Port()); err == nil {
			port = p
		}
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
	_ = json.Unmarshal(resBytes, &gpRes)

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

func fetchIPInfo(ctx context.Context, clientIP string) map[string]any {
	client := engine.GetHTTPClient()
	target := ""
	if clientIP != "" {
		if addr, err := netip.ParseAddr(clientIP); err == nil && !engine.IsRestrictedIP(addr) {
			target = clientIP
		}
	}

	urlWhois := "https://ipwho.is/"
	if target != "" {
		urlWhois = "https://ipwho.is/" + target
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlWhois, nil)
	if err == nil {
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var data struct {
					Success    bool   `json:"success"`
					IP         string `json:"ip"`
					Country    string `json:"country"`
					City       string `json:"city"`
					Connection struct {
						ASN int    `json:"asn"`
						Org string `json:"org"`
						ISP string `json:"isp"`
					} `json:"connection"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.Success {
					isp := data.Connection.ISP
					if isp == "" {
						isp = data.Connection.Org
					}
					asnStr := ""
					if data.Connection.ASN > 0 {
						asnStr = fmt.Sprintf("AS%d", data.Connection.ASN)
						if data.Connection.Org != "" {
							asnStr = fmt.Sprintf("%s (%s)", asnStr, data.Connection.Org)
						}
					}
					ipVal := data.IP
					if ipVal == "" {
						ipVal = clientIP
					}
					return map[string]any{
						"ip":      ipVal,
						"isp":     isp,
						"asn":     asnStr,
						"org":     data.Connection.Org,
						"country": data.Country,
						"city":    data.City,
					}
				}
			}
		}
	}

	urlAPI := "http://ip-api.com/json/?fields=status,message,query,isp,as,org,country,city"
	if target != "" {
		urlAPI = fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,query,isp,as,org,country,city", target)
	}

	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, urlAPI, nil)
	if err == nil {
		resp, err := client.Do(req2)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var data struct {
					Status  string `json:"status"`
					Query   string `json:"query"`
					Country string `json:"country"`
					City    string `json:"city"`
					ISP     string `json:"isp"`
					Org     string `json:"org"`
					AS      string `json:"as"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.Status == "success" {
					isp := data.ISP
					if isp == "" {
						isp = data.Org
					}
					ipVal := data.Query
					if ipVal == "" {
						ipVal = clientIP
					}
					return map[string]any{
						"ip":      ipVal,
						"isp":     isp,
						"asn":     data.AS,
						"org":     data.Org,
						"country": data.Country,
						"city":    data.City,
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

	if engine.IsRestrictedIP(addr) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "forbidden",
			"message": "RFC 1918 Forbidden: Geolocation and ASN lookups are not supported for private/loopback IPs",
		})
		return
	}

	client := engine.GetHTTPClient()
	apiKey := strings.TrimSpace(os.Getenv("IPWHOIS_API_KEY"))

	urlPrimary := fmt.Sprintf("https://ipwho.is/%s", ipStr)
	if apiKey != "" {
		urlPrimary = fmt.Sprintf("https://ipwhois.pro/%s?key=%s", ipStr, apiKey)
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, urlPrimary, nil)
	if err == nil {
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var data map[string]any
				if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
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

	fallbackURL := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as,query", ipStr)
	req2, err := http.NewRequestWithContext(r.Context(), http.MethodGet, fallbackURL, nil)
	if err == nil {
		resp, err := client.Do(req2)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var data struct {
					Status     string  `json:"status"`
					Query      string  `json:"query"`
					Country    string  `json:"country"`
					RegionName string  `json:"regionName"`
					City       string  `json:"city"`
					Lat        float64 `json:"lat"`
					Lon        float64 `json:"lon"`
					Timezone   string  `json:"timezone"`
					ISP        string  `json:"isp"`
					Org        string  `json:"org"`
					AS         string  `json:"as"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.Status == "success" {
					var asnVal any
					if strings.HasPrefix(data.AS, "AS") {
						parts := strings.SplitN(data.AS, " ", 2)
						if num, err := strconv.Atoi(strings.TrimPrefix(parts[0], "AS")); err == nil {
							asnVal = num
						}
					}
					ipType := "IPv4"
					if strings.Contains(ipStr, ":") {
						ipType = "IPv6"
					}

					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"ip":        data.Query,
						"success":   true,
						"type":      ipType,
						"continent": "",
						"country":   data.Country,
						"region":    data.RegionName,
						"city":      data.City,
						"latitude":  data.Lat,
						"longitude": data.Lon,
						"is_eu":     false,
						"asn":       asnVal,
						"org":       data.Org,
						"isp":       data.ISP,
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

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		if n > math.MaxInt || n < math.MinInt {
			return 0
		}
		return int(n)
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || n > float64(math.MaxInt) || n < float64(math.MinInt) {
			return 0
		}
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	default:
		return 0
	}
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		f, _ := strconv.ParseFloat(n, 64)
		return f
	default:
		return 0.0
	}
}
