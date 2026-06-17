# NetCheck Deployment Guide

Quick production deployment with Docker.

## Quick Deploy

```bash
# Pull and run
docker run -d -p 7070:7070 --name netcheck xyzulu/netcheck:latest

# Or with docker-compose
curl -O https://raw.githubusercontent.com/sudo-Penguin-Lalala/netcheck/main/docker-compose.yml
docker compose up -d
```

Open <http://your-server-ip:7070>.

## Environment Variables (Optional)

Pass via `-e` flag or create `.env` file:

| Variable           | Default      | Description                                                   |
| ------------------ | ------------ | ------------------------------------------------------------- |
| `RATE_LIMIT`       | `10/minute`  | Per-IP rate limit. Format: `<n>/<second\|minute\|hour\|day>` |
| `GLOBALPING_TOKEN` | unset        | Optional token from https://globalping.io for higher limits   |
| `AUTH_TOKEN`       | unset        | Bearer token for API access (unlocks RFC1918 targets)         |
| `ALLOWED_ORIGINS`  | empty        | CORS origins. Empty = same-origin, `*` = any origin          |

Example with env vars:

```bash
docker run -d -p 7070:7070 \
  -e RATE_LIMIT=20/minute \
  -e GLOBALPING_TOKEN=your_token \
  --name netcheck xyzulu/netcheck:latest
```

## Reverse Proxy (Optional)

### Caddy

```
netcheck.example.com {
    reverse_proxy localhost:7070
}
```

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

# Update
docker pull xyzulu/netcheck:latest
docker restart netcheck

# Stop
docker stop netcheck
docker rm netcheck
```
