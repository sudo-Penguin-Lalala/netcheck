package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsconf"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/sudo-Penguin-Lalala/netcheck/internal/engine"
)

var allowedDNSTypes = map[string]uint16{
	"A":      dns.TypeA,
	"AAAA":   dns.TypeAAAA,
	"MX":     dns.TypeMX,
	"NS":     dns.TypeNS,
	"CNAME":  dns.TypeCNAME,
	"TXT":    dns.TypeTXT,
	"SOA":    dns.TypeSOA,
	"CAA":    dns.TypeCAA,
	"SRV":    dns.TypeSRV,
	"PTR":    dns.TypePTR,
	"HTTPS":  dns.TypeHTTPS,
	"SVCB":   dns.TypeSVCB,
	"DNSKEY": dns.TypeDNSKEY,
	"DS":     dns.TypeDS,
}

func getSystemResolver() string {
	config, err := dnsconf.FromFile("/etc/resolv.conf")
	if err == nil && len(config.Servers) > 0 {
		port := config.Port
		if port == "" {
			port = "53"
		}
		return net.JoinHostPort(config.Servers[0], port)
	}
	return "1.1.1.1:53"
}

func normalizeResolver(server string) string {
	s := strings.TrimSpace(server)
	if s == "" {
		return getSystemResolver()
	}
	// Pure IPv4 or IPv6 without port
	if ip, err := netip.ParseAddr(s); err == nil {
		return net.JoinHostPort(ip.String(), "53")
	}
	// Already bracketed host:port, e.g. "[::1]:53" or "1.1.1.1:53"
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	// Unbracketed IPv6 with port, e.g. "64:ff9b::127.0.0.1:53" or "::1:53"
	if idx := strings.LastIndex(s, ":"); idx != -1 {
		hostPart := s[:idx]
		portPart := s[idx+1:]
		if ip, err := netip.ParseAddr(hostPart); err == nil {
			return net.JoinHostPort(ip.String(), portPart)
		}
	}
	// Hostname without port, e.g. "one.one.one.one"
	if !strings.Contains(s, ":") {
		return net.JoinHostPort(s, "53")
	}
	return s
}

func validateResolverSecurity(ctx context.Context, serverAddr string) (string, error) {
	host, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return "", fmt.Errorf("invalid resolver format %q: %w", serverAddr, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid resolver port %q", portStr)
	}

	if engine.AllowPrivateTargets() {
		return serverAddr, nil
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		if engine.IsRestrictedIP(ip) {
			return "", engine.ErrRestrictedIP
		}
		return serverAddr, nil
	}

	if ip, ok := engine.ParseLooseIPv4(host); ok {
		if engine.IsRestrictedIP(ip) {
			return "", engine.ErrRestrictedIP
		}
		return net.JoinHostPort(ip.String(), portStr), nil
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve custom dns resolver %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for dns resolver %q", host)
	}

	for _, ipAddr := range ips {
		if addr, ok := netip.AddrFromSlice(ipAddr.IP); ok {
			if engine.IsRestrictedIP(addr) {
				return "", engine.ErrRestrictedIP
			}
		}
	}
	return serverAddr, nil
}

func formatRR(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.Addr.String()
	case *dns.AAAA:
		return v.Addr.String()
	case *dns.CNAME:
		return strings.TrimSuffix(v.Target, ".")
	case *dns.NS:
		return strings.TrimSuffix(v.Ns, ".")
	case *dns.PTR:
		return strings.TrimSuffix(v.Ptr, ".")
	case *dns.TXT:
		return strings.Join(v.Txt, " ")
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			strings.TrimSuffix(v.Ns, "."),
			strings.TrimSuffix(v.Mbox, "."),
			v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *dns.CAA:
		return fmt.Sprintf("%d %s %q", v.Flag, v.Tag, v.Value)
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, strings.TrimSuffix(v.Target, "."))
	case *dns.DNSKEY:
		return fmt.Sprintf("%d %d %d %s", v.Flags, v.Protocol, v.Algorithm, v.PublicKey)
	case *dns.DS:
		return fmt.Sprintf("%d %d %d %s", v.KeyTag, v.Algorithm, v.DigestType, v.Digest)
	case *dns.HTTPS:
		parts := []string{fmt.Sprint(v.Priority), strings.TrimSuffix(v.Target, ".")}
		for _, val := range v.Value {
			parts = append(parts, val.String())
		}
		return strings.Join(parts, " ")
	case *dns.SVCB:
		parts := []string{fmt.Sprint(v.Priority), strings.TrimSuffix(v.Target, ".")}
		for _, val := range v.Value {
			parts = append(parts, val.String())
		}
		return strings.Join(parts, " ")
	default:
		if rr.Data() != nil {
			return rr.Data().String()
		}
		return rr.String()
	}
}

func setEdns0(msg *dns.Msg, size uint16, do bool) {
	msg.UDPSize = size
	msg.Security = do
}

func reverseAddr(ipStr string) (string, error) {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return "", err
	}
	return dnsutil.ReverseAddr(addr), nil
}

func DnsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Host   string `json:"host"`
		Target string `json:"target"`
		Type   string `json:"type"`
		Server string `json:"server"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}

	target := strings.TrimSpace(req.Host)
	if target == "" {
		target = strings.TrimSpace(req.Target)
	}
	target = strings.TrimRight(target, ".")

	if !isValidHostOrIP(target) {
		JSONError(w, http.StatusBadRequest, "Invalid target host: Must be a valid FQDN (RFC 1123, max 253 chars)")
		return
	}

	rtype := strings.ToUpper(strings.TrimSpace(req.Type))
	if rtype == "" {
		rtype = "A"
	}
	qtype, ok := allowedDNSTypes[rtype]
	if !ok {
		JSONError(w, http.StatusBadRequest, "DNS type must be one of: A, AAAA, MX, NS, CNAME, TXT, SOA, CAA, SRV, PTR, HTTPS, SVCB, DNSKEY, DS")
		return
	}

	var resolverAddr string
	if customServer := strings.TrimSpace(req.Server); customServer != "" {
		validated, err := validateResolverSecurity(r.Context(), normalizeResolver(customServer))
		if err != nil {
			if errors.Is(err, engine.ErrRestrictedIP) {
				HandleError(w, err)
				return
			}
			JSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid DNS resolver: %v", err))
			return
		}
		resolverAddr = validated
	} else {
		resolverAddr = getSystemResolver()
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	m := dns.NewMsg(dnsutil.Fqdn(target), qtype)
	if m == nil {
		JSONError(w, http.StatusBadRequest, fmt.Sprintf("Failed to construct DNS query for %s (%s)", target, rtype))
		return
	}
	m.RecursionDesired = true
	// 1232-byte buffer avoids UDP fragmentation per DNS Flag Day / RFC 8900
	setEdns0(m, 1232, true)

	client := dns.NewClient()
	resp, _, err := client.Exchange(ctx, m, "udp", resolverAddr)

	// Retry over TCP if truncated
	if resp != nil && resp.Truncated {
		resp, _, err = client.Exchange(ctx, m, "tcp", resolverAddr)
	}

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			JSONError(w, http.StatusGatewayTimeout, "DNS Timeout: Upstream resolver did not respond within 5000ms")
			return
		}
		JSONError(w, http.StatusBadGateway, fmt.Sprintf("DNS resolution failed: %v", err))
		return
	}

	if resp == nil {
		JSONError(w, http.StatusBadGateway, "DNS resolution failed: empty response from resolver")
		return
	}

	if resp.Rcode == dns.RcodeNameError {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "nxdomain",
			"message": fmt.Sprintf("NXDOMAIN: Domain '%s' does not exist on authoritative nameservers", target),
		})
		return
	}

	var records []string
	var ttl uint32
	for _, ans := range resp.Answer {
		if dns.RRToType(ans) == qtype {
			records = append(records, formatRR(ans))
			if ttl == 0 && ans.Header() != nil {
				ttl = ans.Header().TTL
			}
		}
	}

	if len(records) == 0 {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "no_answer",
			"message": fmt.Sprintf("NODATA: Query succeeded (NOERROR) but no %s record exists for '%s'", rtype, target),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"records":  records,
		"ttl":      ttl,
		"resolver": resolverAddr,
	})
}

func RdnsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		IP     string `json:"ip"`
		Target string `json:"target"`
		Server string `json:"server"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}

	ipStr := strings.TrimSpace(req.IP)
	if ipStr == "" {
		ipStr = strings.TrimSpace(req.Target)
	}

	arpa, err := reverseAddr(ipStr)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "Invalid IP address: Must be a valid IPv4 or IPv6 format")
		return
	}

	var resolverAddr string
	if customServer := strings.TrimSpace(req.Server); customServer != "" {
		validated, err := validateResolverSecurity(r.Context(), normalizeResolver(customServer))
		if err != nil {
			if errors.Is(err, engine.ErrRestrictedIP) {
				HandleError(w, err)
				return
			}
			JSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid DNS resolver: %v", err))
			return
		}
		resolverAddr = validated
	} else {
		resolverAddr = getSystemResolver()
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	m := dns.NewMsg(arpa, dns.TypePTR)
	if m == nil {
		JSONError(w, http.StatusBadRequest, fmt.Sprintf("Failed to construct reverse DNS query for %s", ipStr))
		return
	}
	m.RecursionDesired = true
	setEdns0(m, 1232, false)

	client := dns.NewClient()
	resp, _, err := client.Exchange(ctx, m, "udp", resolverAddr)
	if resp != nil && resp.Truncated {
		resp, _, err = client.Exchange(ctx, m, "tcp", resolverAddr)
	}

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			JSONError(w, http.StatusGatewayTimeout, "rDNS Timeout: Resolver did not respond within 5000ms")
			return
		}
		JSONError(w, http.StatusBadGateway, fmt.Sprintf("rDNS lookup failed: %v", err))
		return
	}

	if resp == nil || len(resp.Answer) == 0 || resp.Rcode == dns.RcodeNameError {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "no_ptr",
			"message": fmt.Sprintf("NODATA: No PTR (Reverse DNS) record configured for IP %s", ipStr),
		})
		return
	}

	var hostname string
	for _, ans := range resp.Answer {
		if ptr, ok := ans.(*dns.PTR); ok {
			hostname = strings.TrimSuffix(ptr.Ptr, ".")
			break
		}
	}

	if hostname == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "no_ptr",
			"message": fmt.Sprintf("NODATA: No PTR (Reverse DNS) record configured for IP %s", ipStr),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"ip":       ipStr,
		"hostname": hostname,
	})
}
