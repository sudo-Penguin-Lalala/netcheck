# NetCheck Security Architecture & Threat Model

This document outlines the security specifications, threat boundaries, and hardening mechanisms implemented in NetCheck. Operators planning to deploy NetCheck in public or production environments should review these guidelines before exposing services beyond loopback interfaces.

---

## 1. Vulnerability Reporting

Please report potential security vulnerabilities through **private security advisories on GitHub**. Avoid filing public issues for unpatched security concerns. Critical reports are reviewed and remediated promptly.

---

## 2. Threat Model & Operational Assumptions

NetCheck is designed as an operator-hosted diagnostic toolkit for network engineers, sysadmins, and homelab environments. The system architecture operates under the following threat model:

1. **Host & Reverse Proxy Trust:** Traffic between NetCheck and its reverse proxy occurs across trusted local channels (loopback `127.0.0.1`, isolated Docker bridge networks, or private VLANs).
2. **Untrusted Client Ingress:** Public ingress traffic is treated as untrusted. Public access must either be authenticated via `AUTH_TOKEN` or governed by strict per-IP rate limiting (`RATE_LIMIT`).
3. **SSRF Boundary Enforcement:** Diagnostic endpoints capable of querying IP addresses or hostnames (`ping`, `traceroute`, `mtr`, `port`, `ssl`, `http`) represent potential Server-Side Request Forgery (SSRF) vectors if left unconstrained. Consequently, private and loopback targets are blocked by default.

---

## 3. Trust Boundaries & Control Parameters

| Boundary | Control Parameter | Default Value | Security Implication |
| :--- | :--- | :--- | :--- |
| **API Ingress Authentication** | `AUTH_TOKEN` | Unset (Open) | When configured, requires `Authorization: Bearer <token>` on all `/api/*` routes. |
| **Proxy Header Trust** | `TRUSTED_PROXIES` | `127.0.0.1,172.16.0.0/12` | Scopes IP extraction from `X-Forwarded-For`. Restricts spoofing to verified reverse proxies. |
| **Private / Subnet Gating** | `ALLOW_PRIVATE_TARGETS` | `0` (Strictly Blocked) | Prevents SSRF attacks against internal network infrastructure. |
| **Client Rate Limiting** | `RATE_LIMIT` | `10/minute` | Per-client request budget enforced across endpoints via in-memory sliding window. |
| **CORS Access Policy** | `ALLOWED_ORIGINS` | Empty (Same-Origin) | Restricts cross-origin resource sharing to designated domains. |
| **Access Logging** | `ACCESS_LOG` | `0` (Zero-Log Mode) | Disables web server access logs to prevent client IP retention. |

---

## 4. Hardening & Defense Mechanisms

### Strict Server-Side Request Forgery (SSRF) Defense
- All target parameters pass through strict hostname and IP validation before any network operation begins.
- By default (`ALLOW_PRIVATE_TARGETS=0`), targets within RFC1918 (IPv4 private), RFC4193 (IPv6 unique local), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), multicast, broadcast, and reserved address spaces are rejected with **HTTP 403 Forbidden** (`error: private_blocked`).
- Setting `ALLOW_PRIVATE_TARGETS=1` activates internal scanning for authorized homelab or private enterprise environments, utilizing local non-blocking socket checks rather than external probes.

### Dual-Resolution DNS Rebinding Protection
To prevent DNS rebinding attacks where an attacker alternates DNS responses between a public IP and an internal address:
- Hostnames are resolved across multiple passes with an interleaved timing jitter delay.
- If any resolved address falls into a private or reserved range, the request is immediately aborted.
- A consistency verification algorithm compares address sets across lookups, incorporating GeoDNS pool heuristics to distinguish benign multi-IP CDNs (e.g. Google, Cloudflare) from single-host rebinding exploits. Resolution failures fail closed (`blocking as fail-closed`).

### IPv6-Mapped IPv4 Normalization
- Inputs formatted as IPv6-mapped IPv4 addresses (e.g., `::ffff:127.0.0.1` or `::ffff:192.168.1.1`) are normalized to standard IPv4 objects prior to evaluation, closing bypass attempts targeting dual-stack network stacks.

### Timing-Safe Authentication
- Bearer token verification uses constant-time string comparison (`secrets.compare_digest`), preventing timing side-channel attacks that exploit early-exit byte comparisons.

### Information Exposure Prevention (CWE-209 / CWE-497)
- Exception messages and internal stack traces are suppressed in API responses, presenting sanitized client-facing error codes while logging diagnostic details strictly to server-side output.

### HTTP Header Sanitization
- The `/api/headers` diagnostic endpoint explicitly strips sensitive client headers (`Authorization`, `Cookie`, `Proxy-Authorization`) prior to returning reflected headers, preventing credential exposure in shared or logged sessions.

### WHOIS Referral Sandboxing
- The raw WHOIS query fallback enforces strict response size limits (capped at 512 KB) to defend against memory exhaustion attacks from untrusted registries.
- Secondary referral referrals to private or loopback endpoints are blocked.

### Edge Content-Security-Policy (CSP)
- NetCheck emits strict Content-Security-Policy headers restricting script execution (`script-src 'self'`), typography (`font-src 'self'`, 100% self-hosted local fonts), framing (`frame-ancestors 'none'`), base URIs (`base-uri 'self'`), and network connect targets (`connect-src 'self' https://ipv4.icanhazip.com https://ipv6.icanhazip.com https://api4.ipify.org https://api6.ipify.org`).

---

## 5. Deployment Topology Matrix

Select the deployment profile matching your infrastructure requirements:

### Profile A: Local Workstation (Loopback Only)
- **Exposure:** Single machine (`127.0.0.1:7070`).
- **Configuration:**
  ```env
  ALLOW_PRIVATE_TARGETS=1
  TRUSTED_PROXIES=
  RATE_LIMIT=60/minute
  ```

### Profile B: Homelab / LAN Diagnostic Gateway
- **Exposure:** Bound to a local subnet (e.g., `192.168.1.0/24`).
- **Configuration:**
  ```env
  AUTH_TOKEN=your-random-32-char-token
  ALLOW_PRIVATE_TARGETS=1
  TRUSTED_PROXIES=
  RATE_LIMIT=30/minute
  ```

### Profile C: Reverse Proxy Edge (Nginx / Caddy / Traefik)
- **Exposure:** Public internet via local reverse proxy with TLS termination.
- **Configuration:**
  ```env
  AUTH_TOKEN=your-random-32-char-token
  ALLOW_PRIVATE_TARGETS=0
  TRUSTED_PROXIES=127.0.0.1
  RATE_LIMIT=10/minute
  ```

### Profile D: Cloud Edge / CDN (Cloudflare Zero Trust / LB)
- **Exposure:** Public internet terminated through an edge CDN.
- **Configuration:**
  ```env
  AUTH_TOKEN=your-random-32-char-token
  ALLOW_PRIVATE_TARGETS=0
  TRUSTED_PROXIES=173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22
  RATE_LIMIT=10/minute
  ```

### Profile E: Public Unauthenticated Demonstration
- **Exposure:** Open web service with strict abuse throttling.
- **Configuration:**
  ```env
  AUTH_TOKEN=
  ALLOW_PRIVATE_TARGETS=0
  TRUSTED_PROXIES=127.0.0.1,172.16.0.0/12
  RATE_LIMIT=5/minute
  ```

---

## 6. Threat Vectors Explicitly Out of Scope

- **Exfiltration of `AUTH_TOKEN`:** If the shared bearer token is compromised, rotate it immediately by updating the environment variable and restarting the container.
- **Target Ping Latency Inference:** Clients authorized to scan custom targets may infer topological latency properties of endpoints they probe.
- **Upstream Measurement Capacity:** High-volume probe utilization is regulated by Globalping's upstream rate limits.

---

## 7. Hardening Verification Checklist

Before publishing NetCheck to an external network:

- [ ] `AUTH_TOKEN` configured with high entropy (e.g., `openssl rand -hex 32`).
- [ ] `ALLOW_PRIVATE_TARGETS=0` confirmed unless specifically provisioning an internal homelab auditor.
- [ ] `TRUSTED_PROXIES` restricted to actual reverse proxy CIDR addresses; verified that wildcard (`*`) is **not** used.
- [ ] HTTPS enforced upstream with modern TLS parameters (TLS 1.2+).
- [ ] Container executing as unprivileged user `netcheck` (`uid: 1000`).
- [ ] `ACCESS_LOG=0` maintained to enforce zero-log data retention.
