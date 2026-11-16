package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sudo-Penguin-Lalala/netcheck/internal/engine"
)

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

var ErrInvalidTarget = errors.New("invalid target: must be a valid IPv4, IPv6, or FQDN")

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

	if errors.Is(err, ErrInvalidTarget) {
		JSONError(w, http.StatusBadRequest, err.Error())
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
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	s = strings.ReplaceAll(s, "%25", "%")
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
	target = strings.TrimSpace(target)
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		target = target[1 : len(target)-1]
	}
	target = strings.ReplaceAll(target, "%25", "%")

	if !isValidHostOrIP(target) {
		return ErrInvalidTarget
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
