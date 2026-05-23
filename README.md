# NetCheck

> Self-hosted single-page network diagnostic toolkit. DNS, ping, traceroute, MTR, port, reverse DNS, WHOIS, headers, SSL, HTTP — one tab, no accounts, your IP never reaches the target.

![NetCheck Screenshot](mainpage.png)

## Demo

Live public demo available at: [netcheck.nnt25.io.vn](https://netcheck.nnt25.io.vn)

> [!NOTE]
> **Privacy Note:** History is stored in your browser's localStorage only (not on the server). Your queries are private to your browser and not visible to other users. However, on a public demo, your queries do reach the demo server's backend and may appear in server logs. For maximum privacy, self-host your own instance.

## Features

- **Origin-leak-free probes** — ping, traceroute, MTR, port-check, SSL, and HTTP all go through the [Globalping](https://globalping.io) API, so the target sees a third-party probe IP, not your server.
- **Probe location selector** — Worldwide (default) / NA / EU / AS / SA / AF / OC on every probe-style tab.
- **Live spinner with elapsed-time counter** on every Globalping-backed request (3-5 s typical round-trip).
- **10 tools in one page** — DNS lookup, Ping, Traceroute, MTR, Port check, Reverse DNS, WHOIS (with IANA two-hop fallback and a friendly message for ccTLDs that publish no WHOIS server), Headers, SSL certificate inspector, HTTP response checker.
- **WHOIS resilience** — falls back to a raw `whois.iana.org` → TLD-server socket query when `python-whois` doesn't know a TLD.
- **No accounts, no cookies, no tracking** — see the Privacy section.
- **Terminal aesthetic** — dark by default, JetBrains Mono, amber accent, sharp corners, full keyboard navigation.
- **Shareable URLs** — every successful run encodes its inputs in the URL; reload the page and it re-runs.
- **History** — last 10 runs in `localStorage`, click any to re-run.
- **WCAG-friendly** — semantic HTML, `role=tablist`, `aria-busy` on result, keyboard shortcuts dialog (`?`).

## Quick start

### Docker run

```bash
docker run -d -p 7070:7070 --name netcheck nnt25/netcheck:latest
```

### Docker Compose

```yaml
services:
  netcheck:
    image: nnt25/netcheck:latest
    container_name: netcheck
    restart: unless-stopped
    ports:
      - "7070:7070"
```

Save as `docker-compose.yml`, then `docker compose up -d`.

Open <http://localhost:7070>.

## Environment variables

| Variable           | Default                          | Effect                                                                                                                              |
| ------------------ | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `AUTH_TOKEN`       | unset                            | When set, every `/api/*` request requires `Authorization: Bearer <token>`. Also unlocks RFC1918/loopback targets (trusted deploy). |
| `RATE_LIMIT`       | `10/minute`                      | Per-IP, per-endpoint rate. Format: `<n>/<second\|minute\|hour\|day>`.                                                              |
| `ALLOWED_ORIGINS`  | empty                            | CORS: empty = same-origin only, `*` = any origin, comma-separated list otherwise.                                                  |
| `GLOBALPING_TOKEN` | unset                            | Optional. Anonymous Globalping = 250 measurements/h; sign-in raises the cap. Get a token at <https://globalping.io>.                |
| `GLOBALPING_API`   | `https://api.globalping.io/v1`   | Override the Globalping API base URL (rarely needed).                                                                              |

## API endpoints

`location` is optional on probe-style endpoints. Valid magic codes: `world` (default, no constraint), `NA`, `EU`, `AS`, `SA`, `AF`, `OC`.

| Method | Path              | Body                                            | Returns                                                                                                    | Privacy                              |
| ------ | ----------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| GET    | `/api/ip`         | —                                               | `{ ip, isp, asn, country, city }`                                                                          | Direct (your IP → ip-api.com)        |
| POST   | `/api/dns`        | `{ host, type }`                                | `{ records, ttl, resolver }`                                                                               | Direct (origin DNS resolver)         |
| POST   | `/api/ping`       | `{ host, count, location? }`                    | `{ host, packets_sent, packets_recv, loss_pct, min, avg, max, raw }`                                       | **Globalping (no origin leak)**      |
| POST   | `/api/traceroute` | `{ host, max_hops, location? }`                 | `{ hops: [{ n, ip, hostname, latency_ms }] }`                                                              | **Globalping (no origin leak)**      |
| POST   | `/api/mtr`        | `{ host, location? }`                           | `{ host, hops: [{ n, ip, hostname, loss_pct, avg_ms, best_ms, worst_ms }] }`                               | **Globalping (no origin leak)**      |
| POST   | `/api/port`       | `{ host, port, timeout, location? }`            | `{ host, port, status }` (`open` / `closed` / `timeout`)                                                   | **Globalping (no origin leak)**      |
| POST   | `/api/rdns`       | `{ ip }`                                        | `{ ip, hostname }`                                                                                         | Direct (origin DNS resolver)         |
| POST   | `/api/whois`      | `{ target }`                                    | `{ raw, registrar, created, expires, nameservers }`                                                        | Direct (origin → TCP 43)             |
| GET    | `/api/headers`    | —                                               | `{ headers: { … } }`                                                                                       | Loopback only                        |
| POST   | `/api/ssl`        | `{ host, port, timeout, location? }`            | `{ host, port, subject, issuer, valid_from, valid_until, days_remaining, expired, san }`                   | **Globalping (no origin leak)**      |
| POST   | `/api/http`       | `{ url, location? }`                            | `{ url, status_code, status_text, response_time_ms, redirects, headers, tls }`                             | **Globalping (no origin leak)**      |
| GET    | `/api/healthz`    | —                                               | `{ status: "ok" }`                                                                                         | Loopback (Docker healthcheck)        |

All errors return `{ "error": "<code>", "message": "<human-readable>" }` with HTTP 400 / 401 / 403 / 422 / 429 / 500 / 502 / 504.

## Privacy

NetCheck is built so anyone can run it without leaking who they are.

**What never leaves your server**
- Your search history, your input values, and every API response stay on the client (`localStorage`, in-memory cache only). Nothing is logged, persisted, or forwarded.
- No analytics, no telemetry, no tracking pixels.
- No third-party scripts; the only off-origin resource is Google Fonts (JetBrains Mono stylesheet + WOFF files). Block it at your reverse proxy if you want zero off-origin requests.

**What does connect outward**
- **Globalping API** (`api.globalping.io`) — receives the target host/IP/URL you typed; runs the actual probe from a third-party node so the target never sees your origin.
- **ip-api.com** (`/api/ip` only) — plain GET, no API key, returns your egress IP + GeoIP. Used to populate the "Your connection" card.
- **`whois.iana.org` and TLD WHOIS servers** (`/api/whois`) — TCP 43 from your origin. Same caveat as any WHOIS client.
- **Origin DNS resolver** (`/api/dns`, `/api/rdns`) — your server's normal DNS path.

The **WHOIS** and **Reverse DNS** tabs carry a small "⚠ Connects directly from your server" label in the UI so users know which queries originate from the host vs. from a remote probe.

**Local storage (browser)**
- `nc.history.v1` — last 10 runs (tool + inputs + summary), capped at 10, FIFO.
- `nc.tab.v1` — which tab was active.
- `nc.theme.v1` — `light` or `dark`.

No cookies. No fingerprinting. No background beacons. The WebRTC local-IP discovery is best-effort and runs in the browser only (modern browsers mDNS-mask private addresses; the UI labels this output `browser-detected`).

**Hardening that ships by default**
- Content-Security-Policy: `default-src 'self'` (Google Fonts whitelisted only for style+font, nothing else).
- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()`.
- Same-origin guard middleware rejects `/api/*` requests whose `Origin`/`Referer` doesn't match the server `Host` (bypass via `AUTH_TOKEN` Bearer or `ALLOWED_ORIGINS=*`).
- Per-IP `slowapi` rate limit, 10 req/min/endpoint by default.
- RFC1918 / loopback / link-local / multicast / reserved targets blocked on probe-style endpoints when `AUTH_TOKEN` is unset.

## Tech stack

- **Backend**: Python 3.11 · FastAPI · uvicorn · slowapi · dnspython · python-whois · httpx (all version-pinned in `backend/requirements.txt`).
- **Frontend**: vanilla HTML + CSS + JS module. No framework. No build step. No bundler.
- **Probes**: Globalping public API (free anonymous tier, optional token for higher limits).
- **Container**: `python:3.11-slim`, single stage, non-root `netcheck:1000` user, JSON healthcheck.

## Reverse-proxy notes

`/api/ip` reads `X-Forwarded-For` / `X-Real-IP`. If you put NetCheck behind nginx / Caddy / Traefik, set one of those headers.

The shipped uvicorn command already passes `--proxy-headers --forwarded-allow-ips=*` so the rate-limiter keys off the real client IP, not the proxy.

Caddyfile example:

```
netcheck.example.com {
    reverse_proxy 127.0.0.1:7070
}
```

## Layout

```
netcheck/
├── backend/
│   ├── main.py             # FastAPI app + security headers + same-origin guard
│   ├── routers/            # one file per /api/* endpoint (11 routes)
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
├── .gitignore
├── LICENSE                 # AGPL v3
└── README.md
```

## What it isn't

- Not a speed test.
- Not a DNS propagation checker.
- Not a graphical traceroute / GeoIP map.
- Not multi-user. No accounts, no audit log, no quota beyond per-IP rate limiting.

If you need those, this is the wrong tool.

## License

AGPL-3.0 © 2026 NNT. See [LICENSE](./LICENSE) for the full text.
