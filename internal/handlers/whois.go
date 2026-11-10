package handlers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/sudo-Penguin-Lalala/netcheck/internal/engine"
	"golang.org/x/sync/singleflight"
)

const (
	maxWhoisBytes = 512 * 1024
	whoisTimeout  = 6 * time.Second
)

type WhoisResult struct {
	Registrar   *string  `json:"registrar"`
	Created     *string  `json:"created"`
	Expires     *string  `json:"expires"`
	Nameservers []string `json:"nameservers"`
	Raw         string   `json:"raw"`
}

var (
	whoisCache = expirable.NewLRU[string, WhoisResult](5000, nil, 12*time.Hour)
	whoisGroup singleflight.Group
)

func WhoisHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Target string `json:"target"`
		Host   string `json:"host"`
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	target := strings.TrimSpace(req.Target)
	if target == "" {
		target = strings.TrimSpace(req.Host)
	}
	if target == "" {
		target = strings.TrimSpace(req.Domain)
	}
	target = strings.ToLower(strings.TrimRight(target, "."))

	if !isValidHostOrIP(target) {
		JSONError(w, http.StatusBadRequest, "Invalid domain name or IP target for WHOIS lookup")
		return
	}

	if cached, ok := whoisCache.Get(target); ok {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(cached)
		return
	}

	resultVal, err, _ := whoisGroup.Do(target, func() (any, error) {
		if cached, ok := whoisCache.Get(target); ok {
			return cached, nil
		}

		rdapCtx, rdapCancel := context.WithTimeout(context.Background(), 5*time.Second)
		res, rdapErr := queryRDAP(rdapCtx, target)
		rdapCancel()
		if rdapErr == nil && res != nil {
			whoisCache.Add(target, *res)
			return *res, nil
		}

		rawCtx, rawCancel := context.WithTimeout(context.Background(), 7*time.Second)
		res, rawErr := queryRawWhois(rawCtx, target)
		rawCancel()
		if rawErr == nil && res != nil {
			whoisCache.Add(target, *res)
			return *res, nil
		}

		// Don't poison the 12h LRU cache on transient network failures
		if rawErr != nil {
			return nil, fmt.Errorf("whois failed: %w", rawErr)
		}
		if rdapErr != nil {
			return nil, fmt.Errorf("rdap failed: %w", rdapErr)
		}

		return nil, errors.New("unable to retrieve WHOIS or RDAP records for target domain")
	})

	if err != nil {
		HandleError(w, err)
		return
	}

	res, ok := resultVal.(WhoisResult)
	if !ok {
		JSONError(w, http.StatusInternalServerError, "Internal error processing WHOIS result")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(res)
}

func queryRDAP(ctx context.Context, target string) (*WhoisResult, error) {
	url := fmt.Sprintf("https://rdap.org/domain/%s", target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")

	resp, err := engine.GetHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxWhoisBytes))
	if err != nil {
		return nil, err
	}

	var data struct {
		Entities []struct {
			Roles      []string `json:"roles"`
			Handle     string   `json:"handle"`
			VcardArray []any    `json:"vcardArray"`
		} `json:"entities"`
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Nameservers []struct {
			LdhName string `json:"ldhName"`
		} `json:"nameservers"`
	}

	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return nil, err
	}

	var registrar *string
	for _, ent := range data.Entities {
		for _, role := range ent.Roles {
			if strings.EqualFold(role, "registrar") {
				name := extractVcardFN(ent.VcardArray)
				if name != "" {
					registrar = &name
				} else if ent.Handle != "" {
					registrar = &ent.Handle
				}
				break
			}
		}
		if registrar != nil {
			break
		}
	}

	var created, expires *string
	for _, ev := range data.Events {
		switch ev.Action {
		case "registration":
			d := ev.Date
			created = &d
		case "expiration":
			d := ev.Date
			expires = &d
		}
	}

	var nameservers []string
	for _, ns := range data.Nameservers {
		if ns.LdhName != "" {
			nameservers = append(nameservers, strings.TrimSuffix(ns.LdhName, "."))
		}
	}

	if registrar == nil && created == nil && expires == nil && len(nameservers) == 0 {
		return nil, errors.New("empty rdap record")
	}

	var prettyBuf bytes.Buffer
	if err := json.Indent(&prettyBuf, bodyBytes, "", "  "); err == nil {
		bodyBytes = prettyBuf.Bytes()
	}

	return &WhoisResult{
		Registrar:   registrar,
		Created:     created,
		Expires:     expires,
		Nameservers: nameservers,
		Raw:         string(bodyBytes),
	}, nil
}

func extractVcardFN(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	items, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, item := range items {
		entry, ok := item.([]any)
		if ok && len(entry) >= 4 {
			if tag, ok := entry[0].(string); ok && tag == "fn" {
				if val, ok := entry[3].(string); ok {
					return val
				}
			}
		}
	}
	return ""
}

func queryRawWhois(ctx context.Context, domain string) (*WhoisResult, error) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid domain for tld referral")
	}
	tld := parts[len(parts)-1]

	ianaRaw, err := sendWhoisTCP(ctx, "whois.iana.org", tld)
	if err != nil {
		return nil, fmt.Errorf("iana query failed: %w", err)
	}

	referralServer := findWhoisField(ianaRaw, "refer", "whois")
	if referralServer == "" {
		return &WhoisResult{
			Raw:         ianaRaw,
			Nameservers: parseWhoisNameservers(ianaRaw),
		}, nil
	}

	serverRaw, err := sendWhoisTCP(ctx, referralServer, domain)
	if err != nil {
		return nil, fmt.Errorf("referral query failed: %w", err)
	}

	reg := findWhoisField(serverRaw, "registrar", "sponsoring registrar", "registrar name", "organisation")
	var registrar *string
	if reg != "" {
		registrar = &reg
	}

	cre := findWhoisField(serverRaw, "created", "creation date", "registered", "registered on", "domain registered", "created on")
	var created *string
	if cre != "" {
		created = &cre
	}

	exp := findWhoisField(serverRaw, "expires", "expiration date", "expiry date", "registry expiry date", "registrar registration expiration date", "expires on")
	var expires *string
	if exp != "" {
		expires = &exp
	}

	return &WhoisResult{
		Registrar:   registrar,
		Created:     created,
		Expires:     expires,
		Nameservers: parseWhoisNameservers(serverRaw),
		Raw:         serverRaw,
	}, nil
}

func sendWhoisTCP(ctx context.Context, server, query string) (string, error) {
	server = strings.TrimSpace(strings.TrimRight(server, "."))
	if server == "" {
		return "", errors.New("empty whois server")
	}

	// Verify the referral server is public before dialing port 43
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, server)
	if err != nil {
		return "", fmt.Errorf("resolve whois server %s: %w", server, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs for whois server %s", server)
	}

	var safeIP netip.Addr
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if ok && !engine.IsRestrictedIP(addr.Unmap()) {
			safeIP = addr.Unmap()
			break
		}
	}
	if !safeIP.IsValid() {
		return "", fmt.Errorf("whois server %s resolved to restricted IP addresses", server)
	}

	dialer := net.Dialer{Timeout: whoisTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(safeIP.String(), "43"))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(whoisTimeout))

	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", err
	}

	out, err := io.ReadAll(io.LimitReader(conn, maxWhoisBytes))
	if err != nil {
		return "", err
	}

	return string(out), nil
}

func findWhoisField(text string, keys ...string) string {
	scanner := bufio.NewScanner(strings.NewReader(text))
	keyMap := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		keyMap[strings.ToLower(k)] = struct{}{}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, ":"); idx != -1 {
			k := strings.ToLower(strings.TrimSpace(line[:idx]))
			if _, ok := keyMap[k]; ok {
				val := strings.TrimSpace(line[idx+1:])
				if val != "" {
					return val
				}
			}
		}
	}
	return ""
}

func parseWhoisNameservers(text string) []string {
	scanner := bufio.NewScanner(strings.NewReader(text))
	targetKeys := map[string]struct{}{
		"name server": {}, "nserver": {}, "nameserver": {}, "name servers": {}, "dns": {},
	}

	seen := make(map[string]struct{})
	var list []string

	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, ":"); idx != -1 {
			k := strings.ToLower(strings.TrimSpace(line[:idx]))
			if _, ok := targetKeys[k]; ok {
				fields := strings.Fields(line[idx+1:])
				if len(fields) > 0 {
					ns := strings.ToLower(strings.TrimSuffix(fields[0], "."))
					if _, exists := seen[ns]; !exists && isValidHostOrIP(ns) {
						seen[ns] = struct{}{}
						list = append(list, ns)
					}
				}
			}
		}
	}
	return list
}
