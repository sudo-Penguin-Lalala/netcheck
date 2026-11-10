# NetCheck Security Architecture & Threat Model

This document outlines the security controls, threat boundaries, and hardening mechanisms in NetCheck v2.0.0. If you are hosting NetCheck on a public server or inside an enterprise network, review this before opening ports to the world.

---

## 1. Vulnerability Reporting

Please report security issues through **GitHub Private Security Advisories**. Do not post unpatched vulnerabilities in public issues or discussions. We review and patch verified reports quickly.

---

## 2. Threat Model & Assumptions

NetCheck provides network diagnostic tools for system administrators and homelab operators. The threat model accounts for four primary risks:

1. **Server-Side Request Forgery (SSRF):** Diagnostic tools take hostnames and IPs from user input. Without strict controls, an attacker could use NetCheck as a proxy to probe private internal subnets, cloud metadata endpoints (`169.254.169.254`), or loopback services.
2. **DNS Rebinding (TOCTOU):** An attacker controls a malicious DNS server that returns a public IP during initial validation, then returns `127.0.0.1` when the socket connection is made.
3. **Cache Poisoning & Upstream DoS:** Attackers spam domain queries to trigger hundreds of concurrent outbound WHOIS socket connections (thundering herd) or poison local caches with bogus records.
4. **Header Spoofing & Abuse:** Attackers forge `X-Forwarded-For` or `CF-Connecting-IP` to bypass rate limits or poison client IP displays.

---

## 3. Defense Mechanisms in Depth

### Custom Loose IPv4 Parser & SSRF Evasion Defense
Standard Go `netip.ParseAddr` strictly expects standard decimal dotted-quad notation (e.g. `127.0.0.1`). If an attacker passes non-standard IPv4 representations—such as octal (`0177.0.0.1`), hex octets (`0x7f.0.0.1`), 32-bit DWORD integers (`2130706433` or `0x7f000001`), or short-form notation (`127.1`)—naive validators fail to parse them as IPs and fall back to treating them as hostnames.

On POSIX platforms, low-level network tools and C-based utilities parse these evasive strings as loopback addresses.

NetCheck defeats this with a custom `ParseLooseIPv4` engine:
- Intercepts all legacy and loose IPv4 notations (octal, hex, DWORD, mixed-radix).
- Canonicalizes them into standard 32-bit addresses.
- Filters them through `IsRestrictedIP`, blocking:
  - RFC 1918 Private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Loopback (`127.0.0.0/8`, `::1`)
  - Unspecified / local routes (`0.0.0.0/8`, `::`)
  - Link-local and cloud metadata (`169.254.0.0/16`, `fe80::/10`)
  - Shared CGNAT address space (`100.64.0.0/10`)
  - Documentation and benchmarking subnets (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15`, `2001:db8::/32`)
  - Class E reserved (`240.0.0.0/4`) and multicast (`224.0.0.0/4`, `ff00::/8`)
- Hostname validation enforces RFC 1123 Section 2.1: **the rightmost label (TLD) can never be all-numeric**, preventing numeric IP formats from masquerading as hostnames.

### Zero-TOCTOU Custom Dialer (`SSRFDialContext`)
To eliminate Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks:
1. When dialing remote targets, `SSRFDialContext` resolves the hostname directly.
2. It inspects all returned IP addresses. If **any** returned IP falls inside a private or restricted subnet, the connection fails closed immediately.
3. If safe, it dials the validated IP address directly on the socket, bypassing secondary hostname lookups.

### IPv4-Mapped IPv6 Unmapping
Attackers frequently submit dual-stack mapped addresses like `::ffff:127.0.0.1` or `::ffff:192.168.1.1` to bypass naive IPv6 prefix filters. NetCheck calls `.Unmap()` on all `netip.Addr` structures before running security checks, stripping the IPv6 prefix down to pure IPv4.

### WHOIS Thundering Herd Protection & Dedicated Deadlines
1. **Singleflight Concurrency Barrier:** Outbound WHOIS lookups are wrapped in a `singleflight.Group`. If 50 users query `example.com` simultaneously, only one upstream query runs; the other 49 callers wait on the single result.
2. **Dedicated Timeouts:** RDAP runs under an independent 5-second context. If RDAP hangs or times out, the port-43 Raw WHOIS query gets its own fresh 7-second context rather than inheriting a dead deadline.
3. **No Poisoning on Failure:** Transient network dropouts and timeouts fail closed and are **never cached** in the 12-hour LRU cache.

### Timing-Safe Authentication
When `AUTH_TOKEN` is enabled, bearer tokens are evaluated using `crypto/subtle.ConstantTimeCompare`:
```go
if subtle.ConstantTimeCompare([]byte(providedToken), []byte(token)) != 1 {
    // 401 Unauthorized
}
```
This prevents timing side-channels that exploit character-by-character string comparisons.

### Strict Proxy Header Validation & Rate Limiting
- `CF-Connecting-IP`, `X-Forwarded-For`, and `X-Real-IP` are only inspected if the direct TCP peer connection matches a subnet in `TRUSTED_PROXIES`.
- Direct connections from untrusted public IPs cannot inject spoofed client addresses; NetCheck discards the fake headers and uses the physical socket IP.
- Rate limiting runs on an in-memory token bucket (`golang.org/x/time/rate`) set to 10 requests per minute with a burst of 5 per client IP. Inactive records are swept every 10 minutes.

### Stateless Scratch Container Isolation
The production image runs `FROM scratch`:
- **Read-Only Root:** Container runs with `read_only: true`.
- **Zero Capabilities:** Runs with `cap_drop: [ALL]`.
- **Unprivileged User:** Executes as UID `10001` (`netcheck`).
- **No Binaries on Disk:** No shell (`/bin/sh`, `/bin/bash`), no package managers (`apk`, `apt`), no interpreters (no Python), and no local disk state.

---

## 4. Configuration Controls Summary

| Control | Parameter | Default | Effect |
| :--- | :--- | :--- | :--- |
| **API Auth** | `AUTH_TOKEN` | Unset | Requires `Authorization: Bearer <token>` on all `/api/*` routes. |
| **Proxy Trust** | `TRUSTED_PROXIES` | Private CIDRs | Only peers in these subnets can forward client IP headers. |
| **Private Scanning** | `ALLOW_PRIVATE_TARGETS` | `0` (Blocked) | When `0`, blocks RFC 1918/loopback. Set `1` for private homelab audits. |
| **CORS Policy** | `ALLOWED_ORIGINS` | Empty | Exact-match origin list. Empty enforces same-origin. |
| **Port Binding** | `PORT` | `8000` | Port for the HTTP listener. |

---

## 5. Security Checklist Before Public Exposure

- [ ] Set `AUTH_TOKEN` to a random high-entropy token (e.g. `openssl rand -hex 32`) if the service should be private.
- [ ] Confirm `ALLOW_PRIVATE_TARGETS=0` to block SSRF against your internal network.
- [ ] Set `TRUSTED_PROXIES` to your specific reverse proxy IP or Cloudflare CIDRs (never use wildcards).
- [ ] Run the container with `read_only: true`, `cap_drop: [ALL]`, and `no-new-privileges:true`.
