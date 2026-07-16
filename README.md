# NetCheck

![Version](https://img.shields.io/github/v/release/sudo-Penguin-Lalala/netcheck?style=flat-square)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)
![Docker](https://img.shields.io/docker/pulls/nnt25/netcheck?style=flat-square)
![Contributors](https://img.shields.io/github/contributors/sudo-Penguin-Lalala/netcheck?style=flat-square)

> Self-hosted network diagnostic toolkit. DNS, ping, traceroute, MTR, port check, WHOIS, reverse DNS, headers, SSL, HTTP, IP lookup — all in one page. Your IP never reaches the target.

![NetCheck Screenshot](mainpage.png)

## Why NetCheck?

Most network diagnostic tools (ping.eu, centralops.net, etc.) run probes **directly from their servers** — which means the target sees their IP, not yours. If you're debugging VPN leaks, firewall rules, or infrastructure issues, you can't trust a tool that doesn't show you what the real world sees.

NetCheck was built to solve exactly this.

| Feature | NetCheck | ping.eu | mxtoolbox |
|---------|----------|---------|-----------|
| Self-hosted | ✅ | ❌ | ❌ |
| Origin-leak-free probes | ✅ (via Globalping) | ❌ | ❌ |
| No tracking / no accounts | ✅ | ❌ | ❌ |
| VPN leak detection | ✅ | ❌ | ❌ |
| 11 tools in one page | ✅ | Partial | Scattered |
| Open source | ✅ AGPL-3.0 | ❌ | ❌ |
| Docker deploy in 1 command | ✅ | ❌ | ❌ |

**Real-world example:** NetCheck caught an Amnezia WireGuard misconfiguration that standard VPN leak tests missed. The VPN client showed "connected" — NetCheck showed the real ISP IP leaking through. The tunnel was broken; no other tool detected it.

## Demo

Live public demo: [netcheck.nnt25.io.vn](https://netcheck.nnt25.io.vn)

> [!NOTE]
> **Privacy Note:** History is stored in your browser's localStorage only (not on the server). Your queries are private to your browser. However, on a public demo, your queries reach the demo server's backend and may appear in server logs. For maximum privacy, self-host your own instance.

## Who is this for?

- **Homelabbers** — diagnose your network without exposing your server IP
- **Sysadmins / DevOps** — quick toolkit without jumping between 10 different sites
- **Privacy-conscious users** — zero tracking, no accounts, self-hosted
- **VPN users** — verify your tunnel actually works (not just what the client says)
- **Hosting providers** — look up IP ownership, run diagnostics, check infrastructure

## Features

- **Origin-leak-free probes** — ping, traceroute, MTR, port check, SSL, and HTTP all go through the [Globalping](https://globalping.io) API. The target sees a third-party probe IP, not your server.
- **Real VPN leak detection** — `/api/ip` detects your actual egress IP even when other tools miss it. Catches misconfigured tunnels that pass basic "what's my IP" checks.
- **IP ownership lookup** — `/api/ip-lookup` reveals who owns any IP address (ASN, org, ISP, location) via ipwhois.io. No API key required for free tier.
- **Probe location selector** — Worldwide (default) / NA / EU / AS / SA / AF / OC on every probe-style tab.
- **11 tools in one page** — DNS lookup, Ping, Traceroute, MTR, Port check, Reverse DNS, WHOIS (with IANA two-hop fallback), Headers, SSL certificate inspector, HTTP response checker, IP lookup.
- **WHOIS resilience** — falls back to a raw `whois.iana.org` → TLD-server socket query when `python-whois` doesn't know a TLD.
- **No accounts, no cookies, no tracking** — see the Privacy section.
- **Terminal aesthetic** — dark by default, JetBrains Mono, amber accent, sharp corners, full keyboard navigation.
- **Shareable URLs** — every successful run encodes its inputs in the URL; reload and it re-runs.
- **History** — last 10 runs in `localStorage`, click any to re-run.
- **WCAG-friendly** — semantic HTML, `role=tablist`, `aria-busy` on result, keyboard shortcuts dialog (`?`).

## Prerequisites

- **Docker** (20.10+) or **Docker Compose** (v2+)
- **Port 7070** available (or change the port mapping)
- **Internet access** for Globalping API, ip-api.com, WHOIS servers

**Optional:**
- Reverse proxy (nginx/Caddy/Traefik) for HTTPS and custom domain
- `AUTH_TOKEN` for internet-facing deploys
- `GLOBALPING_TOKEN` for higher rate limits (250 → 500+ measurements/hour)

## Quick start

### Option 1: Docker run (fastest)

```bash
docker run -d -p 7070:7070 --name netcheck nnt25/netcheck:latest
```

Open <http://localhost:7070> in your browser.

### Option 2: Docker Compose (recommended)

```yaml
services:
  netcheck:
    image: nnt25/netcheck:latest
    container_name: netcheck
    restart: unless-stopped
    ports:
      - "7070:7070"
    environment:
      # AUTH_TOKEN: "your-random-32-char-token-here"
      # ALLOW_PRIVATE_TARGETS: "0"
      # TRUSTED_PROXIES: "127.0.0.1"
      # RATE_LIMIT: "10/minute"
      # GLOBALPING_TOKEN: "your-globalping-token"
      # BKNS_API_KEY: "your-bkns-api-key"
      # IPWHOIS_API_KEY: "your-ipwhois-api-key"
```

```bash
docker compose up -d
```

### First test

1. Click the **DNS** tab → enter `google.com` → click **Run**
2. Click the **IP** tab → enter any IP like `1.1.1.1` → see who owns it
3. Press `?` to see all keyboard shortcuts

---

## Environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `AUTH_TOKEN` | unset | Require `Authorization: Bearer <token>` on all `/api/*` requests |
| `ALLOW_PRIVATE_TARGETS` | `0` | Allow RFC1918/loopback targets. `1` = allow (LAN scanning), `0` = block |
| `TRUSTED_PROXIES` | `127.0.0.1,172.16.0.0/12` | IPs/CIDRs whose `X-Forwarded-For` is trusted for rate limiting |
| `RATE_LIMIT` | `10/minute` | Per-IP per-endpoint rate. Format: `<n>/<second\|minute\|hour\|day>` |
| `ALLOWED_ORIGINS` | empty | CORS: empty = same-origin only, `*` = any, comma-separated list |
| `GLOBALPING_TOKEN` | unset | Optional. Raises probe limit above 250 measurements/hour |
| `GLOBALPING_API` | `https://api.globalping.io/v1` | Override Globalping API base URL |
| `BKNS_API_KEY` | unset | BKNS WHOIS for .vn domains. Without key: 10 req/min, with key: 300 req/min |
| `IPWHOIS_API_KEY` | unset | Optional. Upgrades IP lookup to ipwhois.pro for higher limits |
| `CACHE_DIR` | `/data/netcheck-cache` | Directory for persistent disk cache (used by WHOIS). |

## Security

### Default security — no configuration needed

NetCheck is **secure by default**. Out of the box:

- Private/loopback/link-local IPs blocked on all probe endpoints (`ALLOW_PRIVATE_TARGETS=0`)
- Rate limiting enabled (10 req/min per IP per endpoint)
- Security headers set (CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- Auth headers (`Authorization`, `Cookie`, `Proxy-Authorization`) never reflected back
- WHOIS raw socket capped at 512 KB (prevents memory exhaustion)
- Trusted proxies scoped to localhost + Docker bridge only

You only need to configure if you're exposing to the internet or doing LAN scanning.

### Deployment Scenarios

| Scenario | Use Case | Key Settings |
|----------|----------|--------------|
| **A: Localhost only** | Personal use | `TRUSTED_PROXIES=` (empty) |
| **B: LAN-exposed** | Homelab | `AUTH_TOKEN` + `ALLOW_PRIVATE_TARGETS=1` |
| **C: Host-networking + nginx** | LAN scanning | `TRUSTED_PROXIES=127.0.0.1` + `ALLOW_PRIVATE_TARGETS=1` |
| **D: Docker bridge + nginx** | Standard reverse proxy | `TRUSTED_PROXIES=172.16.0.0/12,127.0.0.1` |
| **E: Behind Cloudflare** | Internet-facing, authenticated | `AUTH_TOKEN` + `ALLOW_PRIVATE_TARGETS=0` + `TRUSTED_PROXIES=<CF-IPs>` |
| **F: Public demo** | Unauthenticated, rate-limited | `ALLOW_PRIVATE_TARGETS=0` + `RATE_LIMIT=5/minute` |
| **G: Kubernetes** | K8s deployment | `AUTH_TOKEN` + `TRUSTED_PROXIES=10.0.0.0/8` |
| **H: Air-gapped lab** | No internet | `ALLOW_PRIVATE_TARGETS=1` |

Full details: [SECURITY.md](./SECURITY.md)

### Pre-deploy checklist for internet-facing installs

- [ ] `AUTH_TOKEN` set to ≥32 random characters (`openssl rand -hex 32`)
- [ ] `ALLOW_PRIVATE_TARGETS=0`
- [ ] `TRUSTED_PROXIES` matches your reverse proxy CIDR, never `*`
- [ ] `RATE_LIMIT` ≤ 10/minute for unauthenticated deploys
- [ ] Reverse proxy enforces HTTPS

---

## API endpoints

`location` is optional on probe-style endpoints. Valid values: `world` (default), `NA`, `EU`, `AS`, `SA`, `AF`, `OC`.

| Method | Path | Body | Returns | Privacy |
|--------|------|------|---------|---------|
| GET | `/api/ip` | — | `{ ip, isp, asn, country, city }` | Direct (your IP → ip-api.com) |
| GET | `/api/ip-lookup?ip=` | — | `{ ip, asn, org, isp, city, country, timezone }` | Direct (→ ipwho.is) |
| POST | `/api/dns` | `{ host, type }` | `{ records, ttl, resolver }` | Direct (origin DNS) |
| POST | `/api/ping` | `{ host, count, location? }` | `{ packets_sent, packets_recv, loss_pct, min, avg, max, raw }` | **Globalping** |
| POST | `/api/traceroute` | `{ host, max_hops, location? }` | `{ hops: [{ n, ip, hostname, latency_ms }] }` | **Globalping** |
| POST | `/api/mtr` | `{ host, location? }` | `{ hops: [{ n, ip, hostname, loss_pct, avg_ms, best_ms, worst_ms }] }` | **Globalping** |
| POST | `/api/port` | `{ host, port, timeout, location? }` | `{ host, port, status }` | **Globalping** |
| POST | `/api/rdns` | `{ ip }` | `{ ip, hostname }` | Direct (origin DNS) |
| POST | `/api/whois` | `{ target }` | `{ raw, registrar, created, expires, nameservers }` | Direct (→ TCP 43) |
| GET | `/api/headers` | — | `{ headers: { … } }` | Loopback only |
| POST | `/api/ssl` | `{ host, port, timeout, location? }` | `{ subject, issuer, valid_from, valid_until, days_remaining, expired, san }` | **Globalping** |
| POST | `/api/http` | `{ url, location? }` | `{ status_code, response_time_ms, redirects, headers, tls }` | **Globalping** |
| GET | `/api/healthz` | — | `{ status: "ok" }` | Loopback |

All errors: `{ "error": "<code>", "message": "<human-readable>" }` with HTTP 400/401/403/422/429/500/502/504.

---

## Privacy

**What never leaves your server:**
- Search history, input values, API responses stay in `localStorage` / in-memory only
- No analytics, no telemetry, no tracking pixels
- No third-party scripts (only Google Fonts for JetBrains Mono — block at reverse proxy for zero off-origin)

**What connects outward:**
- **Globalping API** — receives target host/IP/URL, runs probe from a third-party node
- **ip-api.com** — plain GET for your egress IP + GeoIP
- **ipwho.is** — IP ownership lookup (free tier, no key required)
- **whois.iana.org + TLD WHOIS servers** — TCP 43 for WHOIS queries
- **Origin DNS resolver** — for DNS and reverse DNS lookups

**localStorage keys:**
- `nc.history.v1` — last 10 runs, FIFO
- `nc.tab.v1` — active tab
- `nc.theme.v1` — `light` or `dark`

---

## Tech stack

- **Backend:** Python 3.11 · FastAPI · uvicorn · slowapi · dnspython · python-whois · httpx
- **Frontend:** Vanilla HTML + CSS + JS. No framework. No build step. No bundler.
- **Probes:** Globalping public API (free anonymous tier, optional token for higher limits)
- **Container:** `python:3.11-slim`, single stage, non-root `netcheck:1000` user

---

## Reverse-proxy notes

### Caddy (recommended)

```
netcheck.example.com {
    reverse_proxy 127.0.0.1:7070
}
```

### nginx

```nginx
location / {
    proxy_pass http://127.0.0.1:7070;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

> [!WARNING]
> Set `TRUSTED_PROXIES` to your reverse proxy's IP/CIDR. Never use `*` — it allows any client to forge `X-Forwarded-For` and bypass rate limiting.

---

## Layout

```
netcheck/
├── backend/
│   ├── main.py             # FastAPI app + security headers + same-origin guard
│   ├── routers/            # one file per /api/* endpoint (12 routes)
│   ├── utils/              # validators, rate-limit, Globalping client
│   └── requirements.txt
├── frontend/
│   ├── index.html          # tabs, panels, IP card, shortcuts dialog
│   ├── style.css           # terminal-flavored design tokens
│   ├── app.js              # runners, history, share, theme, spinner
│   └── favicon.svg
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── SECURITY.md
├── LICENSE                 # AGPL v3
└── README.md
```

## What it isn't

- Not a speed test
- Not a DNS propagation checker
- Not a graphical traceroute / GeoIP map
- Not multi-user (no accounts, no audit log)

---

## Troubleshooting

### Container won't start

```bash
docker logs netcheck
```

Common: port 7070 already in use → change mapping to `-p 8080:7070`

### "Your connection" card shows wrong IP

ip-api.com is down or blocked. Will retry on next page load.

### Globalping tools fail (ping/traceroute/MTR/port/SSL/HTTP)

Anonymous limit is 250 measurements/hour. Get a free token at [globalping.io](https://globalping.io) and set `GLOBALPING_TOKEN`.

### Can't scan private IPs

Expected. Private IPs blocked by default. Enable with `ALLOW_PRIVATE_TARGETS=1` (trusted networks only).

### Rate limiting not working behind reverse proxy

`TRUSTED_PROXIES` is misconfigured. Set it to your proxy's IP, never `*`.

### Still stuck?

Open a [GitHub issue](https://github.com/sudo-Penguin-Lalala/netcheck/issues) with:
- Docker version
- Deployment scenario
- Relevant logs (`docker logs netcheck`)
- Environment variables (redact `AUTH_TOKEN`)

---

## Contributing

PRs welcome. NetCheck uses AGPL-3.0 — any modifications must be open-sourced under the same license.

---

## License

AGPL-3.0 © 2026 NNT. See [LICENSE](./LICENSE).
