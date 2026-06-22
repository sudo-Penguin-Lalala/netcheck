# NetCheck Deployment Guide

Quick production deployment with Docker.

## Quick Deploy

```bash
# Pull and run
docker run -d -p 7070:7070 --name netcheck nnt25/netcheck:latest

# Or with docker-compose
curl -O https://raw.githubusercontent.com/sudo-Penguin-Lalala/netcheck/main/docker-compose.yml
docker compose up -d
```

Open <http://your-server-ip:7070>.

## Environment Variables (Optional)

Pass via `-e` flag or `.env` file. All variables are optional — NetCheck is secure by default with no configuration required.

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_TOKEN` | unset | Bearer token required on all `/api/*` requests. Recommended for internet-facing deploys. |
| `ALLOW_PRIVATE_TARGETS` | `0` | Allow RFC1918/loopback targets. `1` = allow (LAN scanning), `0` = block. |
| `TRUSTED_PROXIES` | `127.0.0.1,172.16.0.0/12` | IPs/CIDRs whose `X-Forwarded-For` is trusted for rate limiting. Never use `*`. |
| `RATE_LIMIT` | `10/minute` | Per-IP rate limit. Format: `<n>/<second\|minute\|hour\|day>` |
| `ALLOWED_ORIGINS` | empty | CORS origins. Empty = same-origin only, `*` = any origin. |
| `GLOBALPING_TOKEN` | unset | Optional token from https://globalping.io for higher probe limits (250 → 500+/hour). |
| `BKNS_API_KEY` | unset | Optional BKNS API key for .vn domain WHOIS. Without key: 10 req/min. |
| `IPWHOIS_API_KEY` | unset | Optional ipwhois.pro key for higher IP lookup limits. Free tier works without key. |

Example with env vars:

```bash
docker run -d -p 7070:7070 \
  -e RATE_LIMIT=20/minute \
  -e GLOBALPING_TOKEN=your_token \
  -e TRUSTED_PROXIES=127.0.0.1 \
  --name netcheck nnt25/netcheck:latest
```

## Reverse Proxy (Optional)

> [!WARNING]
> Always set `TRUSTED_PROXIES` to your reverse proxy's IP/CIDR. Never use `*` — it allows any client to forge `X-Forwarded-For` and bypass rate limiting.

### Caddy (recommended)

```
netcheck.example.com {
    reverse_proxy localhost:7070
}
```

Set `TRUSTED_PROXIES=127.0.0.1` in your environment.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name netcheck.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:7070;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Set `TRUSTED_PROXIES=127.0.0.1` in your environment.

### Traefik

```yaml
http:
  routers:
    netcheck:
      rule: "Host(`netcheck.example.com`)"
      service: netcheck
      tls:
        certResolver: letsencrypt

  services:
    netcheck:
      loadBalancer:
        servers:
          - url: "http://localhost:7070"
```

### Apache

```apache
<VirtualHost *:443>
    ServerName netcheck.example.com

    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem

    ProxyPreserveHost On
    ProxyPass / http://localhost:7070/
    ProxyPassReverse / http://localhost:7070/
</VirtualHost>
```

## Maintenance

```bash
# View logs
docker logs netcheck

# Restart
docker restart netcheck

# Update (docker run)
docker pull nnt25/netcheck:latest
docker stop netcheck && docker rm netcheck
docker run -d -p 7070:7070 --name netcheck nnt25/netcheck:latest

# Update (docker compose)
docker compose pull
docker compose up -d

# Stop and remove
docker stop netcheck
docker rm netcheck
```

## Further reading

- [SECURITY.md](./SECURITY.md) — full deployment matrix, threat model, trust boundaries
- [README.md](./README.md) — all environment variables and API reference
