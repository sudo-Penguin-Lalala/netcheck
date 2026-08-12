# NetCheck — Security Notes & Deployment Matrix

This file documents the security model NetCheck assumes, every supported
deployment topology, and the environment variables that govern its trust
boundaries. Read this before exposing NetCheck to anything other than
`127.0.0.1`.

## Reporting

Please open a private security advisory on GitHub (or email the maintainer
listed in `pyproject.toml` / repo `README.md`). Do not file public issues
for unpatched vulnerabilities.

## Threat model

NetCheck is a homelab / single-tenant diagnostic toolkit. It assumes:

- The operator runs it on infrastructure they own.
- Traffic between NetCheck and any reverse proxy is on a trusted network
  (host loopback, Docker bridge, private VLAN).
- The internet-facing surface is **either** authenticated via `AUTH_TOKEN`
  **or** rate-limited well below a single attacker's abuse budget.

It is **not** designed to be a hardened multi-tenant SaaS. If you run it
public + unauthenticated, treat every diagnostic as a potential SSRF /
reconnaissance vector.

## Trust boundaries at a glance

| Boundary | Controlled by | Default |
|---|---|---|
| Who can hit `/api/*` | `AUTH_TOKEN` | Public (no token) |
| Whose `X-Forwarded-For` we trust | `TRUSTED_PROXIES` | `127.0.0.1,172.16.0.0/12` |
| Whether private/loopback targets are scannable | `ALLOW_PRIVATE_TARGETS` (v1.2.0+) | Blocked |
| Per-IP request budget | `RATE_LIMIT` | `10/minute` |
| Cross-origin browser access | `ALLOWED_ORIGINS` | Same-origin |
| Server access logs (IPs/queries) | `ACCESS_LOG` | `0` (Zero-log mode) |

## Environment variables

### `ACCESS_LOG`
Controls whether Uvicorn writes HTTP access logs (client IPs and requested paths) to standard output. 
- `0` (default): Zero-log privacy mode. Visitor IPs are not saved.
- `1`: Enable standard access logs.

### `AUTH_TOKEN`
Opaque bearer token. When set, every `/api/*` request must carry
`Authorization: Bearer <token>` or it is rejected with HTTP 401.

Before v1.2.0, setting this also implicitly opened scans against
RFC1918 / loopback addresses. **As of v1.2.0 this coupling is
deprecated** — see `ALLOW_PRIVATE_TARGETS`.

### `ALLOW_PRIVATE_TARGETS` (new in v1.2.0)
Decoupled SSRF gate. Controls whether `/api/ping`, `/api/traceroute`,
`/api/port`, `/api/mtr` can be aimed at private / loopback / link-local
addresses.

| Value | Effect |
|---|---|
| `1` / `true` / `yes` | Allow private targets |
| `0` / `false` / `no` | Block private targets even if `AUTH_TOKEN` is set |
| unset, `AUTH_TOKEN` unset | Block (default) |
| unset, `AUTH_TOKEN` set | Allow + log a deprecation warning (legacy compat — removed in v2.0) |

If you currently rely on the "set `AUTH_TOKEN` to unlock LAN scans"
behavior, set `ALLOW_PRIVATE_TARGETS=1` explicitly to silence the
warning and survive the v2.0 cleanup.

### `TRUSTED_PROXIES` (new in v1.2.0)
Comma-separated list of source IPs / CIDRs whose `X-Forwarded-For` and
`X-Real-IP` headers NetCheck honors when deriving the rate-limit key.
Passed through to `uvicorn --forwarded-allow-ips`.

| Value | Effect |
|---|---|
| `127.0.0.1,172.16.0.0/12` | Default. Trust host loopback + Docker bridge |
| `192.168.1.10` | Trust exactly one reverse proxy |
| `127.0.0.1,10.0.0.0/8` | Trust loopback + private LAN proxies |
| empty | Ignore proxy headers entirely (use TCP peer) |
| `*` | **Never set this in production.** Lets any client forge XFF and bypass rate limiting |

### `RATE_LIMIT`
`slowapi` per-IP-per-endpoint budget, e.g. `10/minute`. Only as good as
`TRUSTED_PROXIES` is correct — see "Why `TRUSTED_PROXIES=*` is dangerous"
below.

### `ALLOWED_ORIGINS`
CORS allow-list. Empty = same-origin only.

### `GLOBALPING_TOKEN` / `BKNS_API_KEY`
Outbound API credentials. NetCheck reads these at startup; rotating them
requires a container restart.

## Deployment case matrix

Pick the row that matches your topology and copy the `.env` snippet.

### A — Localhost only, no reverse proxy

```
docker run -p 127.0.0.1:7070:7070 ...
```

```ini
AUTH_TOKEN=
ALLOW_PRIVATE_TARGETS=1
TRUSTED_PROXIES=
RATE_LIMIT=60/minute
```

You are the only client; rate limiting is mostly for runaway scripts.

### B — Docker bridge, no reverse proxy, LAN-exposed

```
docker run -p 7070:7070 ...
```

```ini
AUTH_TOKEN=<random-32-char-hex>
ALLOW_PRIVATE_TARGETS=1
TRUSTED_PROXIES=
RATE_LIMIT=10/minute
```

`TRUSTED_PROXIES=` empty means the rate limiter uses the real TCP peer
address — correct for direct LAN access.

### C — Docker host-networking, behind nginx on the host

```yaml
# docker-compose.yml
services:
  netcheck:
    network_mode: host
```

```ini
AUTH_TOKEN=
ALLOW_PRIVATE_TARGETS=1
TRUSTED_PROXIES=127.0.0.1
RATE_LIMIT=10/minute
ALLOWED_ORIGINS=https://netcheck.lab.example.com
```

This is the recommended setup for "I want to scan my own LAN."

### D — Docker bridge, behind nginx on the host

```ini
AUTH_TOKEN=
ALLOW_PRIVATE_TARGETS=1
TRUSTED_PROXIES=172.16.0.0/12,127.0.0.1
RATE_LIMIT=10/minute
ALLOWED_ORIGINS=https://netcheck.lab.example.com
```

Default `TRUSTED_PROXIES` already covers this. Listed for completeness.

### E — Behind Cloudflare / cloud LB, internet-facing

```ini
AUTH_TOKEN=<random-32-char-hex>
ALLOW_PRIVATE_TARGETS=0
TRUSTED_PROXIES=<your-LB-IP-ranges>
RATE_LIMIT=10/minute
ALLOWED_ORIGINS=https://netcheck.example.com
```

`ALLOW_PRIVATE_TARGETS=0` is critical — without it, an authenticated user
can ask NetCheck to scan your internal network from your own server.

### F — Public unauthenticated demo

```ini
AUTH_TOKEN=
ALLOW_PRIVATE_TARGETS=0
TRUSTED_PROXIES=<your-LB-IP-ranges>
RATE_LIMIT=5/minute
ALLOWED_ORIGINS=*
```

Set `RATE_LIMIT` low and watch logs. Treat this as a research demo, not
production.

### G — Kubernetes Ingress (any flavor)

```ini
AUTH_TOKEN=<random-32-char-hex>
ALLOW_PRIVATE_TARGETS=0
TRUSTED_PROXIES=10.0.0.0/8
RATE_LIMIT=10/minute
ALLOWED_ORIGINS=https://netcheck.example.com
```

`10.0.0.0/8` covers the pod and node networks; tighten if your cluster
uses something narrower.

### H — Air-gapped lab

```ini
AUTH_TOKEN=
ALLOW_PRIVATE_TARGETS=1
TRUSTED_PROXIES=
RATE_LIMIT=60/minute
```

No internet → no Globalping → ping/traceroute features will fail. Use
`/api/dns`, `/api/whois` (BKNS for `.vn`), `/api/headers`, `/api/ssl_check`.

## Why `TRUSTED_PROXIES=*` is dangerous

The old default (`--forwarded-allow-ips=*`) trusted every TCP peer's
`X-Forwarded-For` header. An attacker reaching NetCheck directly (or
through a misconfigured LB) could send a fresh `X-Forwarded-For: <random>`
on every request, getting a new rate-limit bucket each time.

The new default (`127.0.0.1,172.16.0.0/12`) only honors XFF when the
TCP peer is something we already expect to be a reverse proxy
(loopback nginx + Docker bridge). Anything else falls back to the real
peer IP.

## Migration from v1.1.x → v1.2.0

```diff
 # .env
-AUTH_TOKEN=mytoken
+AUTH_TOKEN=mytoken
+ALLOW_PRIVATE_TARGETS=1   # preserve the implicit unlock
+TRUSTED_PROXIES=127.0.0.1 # or your real proxy CIDR
```

You will see this in the logs once per process if you do nothing:

```
DEPRECATED: AUTH_TOKEN is enabling private-target access. Set
ALLOW_PRIVATE_TARGETS=1 explicitly to silence this warning, or
ALLOW_PRIVATE_TARGETS=0 to block private targets even with AUTH_TOKEN set.
Legacy coupling will be removed in v2.0.
```

That is harmless — the runtime behavior is unchanged until v2.0.

## Other v1.2.0 hardening

- **WHOIS referral SSRF**: `whois.py` now refuses to open TCP-43 to any
  hostname/IP that resolves into RFC1918, loopback, link-local,
  multicast, or reserved space. A malicious TLD that returns
  `refer: localhost` can no longer pivot through us.
- **WHOIS response cap**: the raw-socket fallback caps responses at
  512 KB to prevent a memory-exhaustion DoS from a misbehaving registry.
- **`/api/headers` reflection**: the endpoint no longer echoes
  `Authorization`, `Cookie`, or `Proxy-Authorization` headers back. Use
  it for diagnosing client-set headers only.
- **DNS-resolver TOCTOU**: `is_private_target_blocked()` now uses a
  per-call `getaddrinfo` timeout (no more process-global
  `socket.setdefaulttimeout` mutation). Concurrent requests no longer
  race the global default.

## Threats we explicitly do not defend against

- Compromise of `AUTH_TOKEN` (rotate it; that's it).
- Side-channel inference of LAN topology from ping latency. If you
  expose NetCheck publicly, an authenticated client can map your
  network within whatever target list you allow.
- Outbound bandwidth abuse via `/api/ping` / `/api/traceroute` — those
  are proxied through Globalping, so it's their problem, not yours.

## Hardening checklist for any non-localhost deploy

- [ ] `AUTH_TOKEN` set to ≥ 32 random characters.
- [ ] `ALLOW_PRIVATE_TARGETS=0` unless you specifically need LAN scans.
- [ ] `TRUSTED_PROXIES` matches your actual reverse-proxy CIDR, never `*`.
- [ ] `ALLOWED_ORIGINS` set to the exact public hostname, never `*`.
- [ ] `RATE_LIMIT` ≤ `10/minute` for unauthenticated deploys.
- [ ] Container runs as non-root (Dockerfile default, don't override).
- [ ] Reverse proxy enforces HTTPS; CSP / HSTS handled at the edge.
- [ ] Logs shipped off-box so you can audit the deprecation warnings.
