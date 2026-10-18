# NetCheck Production Deployment & Operations Guide

This guide details deployment options, reverse proxy configurations, and operational lifecycle procedures for NetCheck.

---

## 1. Quick Start

### Standalone OCI / Docker Container

Deploy with default production settings (unprivileged user, non-root, zero-log mode):

```bash
docker run -d \
  --name netcheck \
  --restart unless-stopped \
  -p 7070:7070 \
  -v netcheck-cache:/data/netcheck-cache \
  nnt25/netcheck:latest
```

The service will bind to TCP port `7070` and initialize immediately.

---

## 2. Docker Compose Deployment (Recommended)

Using Docker Compose ensures reproducible configurations, persistent caching, and graceful orchestration.

Save as `docker-compose.yml`:

```yaml
services:
  netcheck:
    image: nnt25/netcheck:latest
    container_name: netcheck
    restart: unless-stopped
    ports:
      - "127.0.0.1:7070:7070"  # Bind to localhost when paired with a reverse proxy
    environment:
      - ACCESS_LOG=0           # Zero-log privacy mode (default)
      # - AUTH_TOKEN=generate-a-secure-32-byte-hex-string
      # - ALLOW_PRIVATE_TARGETS=0
      # - TRUSTED_PROXIES=127.0.0.1,172.16.0.0/12
      # - RATE_LIMIT=10/minute
      # - GLOBALPING_TOKEN=your-token-from-globalping-io
    volumes:
      - netcheck-cache:/data/netcheck-cache
    healthcheck:
      test: ["CMD-SHELL", "python -c \"import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7070/api/healthz', timeout=3).status == 200 else 1)\""]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

volumes:
  netcheck-cache:
    name: netcheck_cache_data
```

Launch the stack:

```bash
docker compose up -d
```

---

## 3. Reverse Proxy Configuration

When publishing NetCheck externally, terminate TLS and forward requests using a modern reverse proxy.

> [!CRITICAL]
> Always configure `TRUSTED_PROXIES` to reflect the specific IP address or CIDR range of your reverse proxy. **Never set `TRUSTED_PROXIES=*` in production**, as this allows malicious clients to spoof `X-Forwarded-For` and circumvent rate limiting.

### Caddy (Recommended)

Caddy terminates HTTPS automatically and manages certificate renewal.

```caddyfile
netcheck.example.com {
    reverse_proxy 127.0.0.1:7070 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
    }
}
```

*Required Environment:* `TRUSTED_PROXIES=127.0.0.1`

---

### Nginx

Idiomatic configuration with standard proxy headers, HTTP/2, and extended read timeouts for traceroute/MTR probes:

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name netcheck.example.com;

    ssl_certificate     /etc/ssl/certs/netcheck.crt;
    ssl_certificate_key /etc/ssl/private/netcheck.key;

    # Recommended TLS Parameters
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass         http://127.0.0.1:7070;
        proxy_http_version 1.1;

        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Traceroute and MTR telemetry may require up to 45s for deep path discovery
        proxy_read_timeout 60s;
        proxy_connect_timeout 10s;
    }
}
```

*Required Environment:* `TRUSTED_PROXIES=127.0.0.1`

---

### Traefik v3 (File Provider)

```yaml
http:
  routers:
    netcheck-secure:
      rule: "Host(`netcheck.example.com`)"
      entryPoints:
        - websecure
      service: netcheck-service
      tls:
        certResolver: letsencrypt

  services:
    netcheck-service:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:7070"
```

---

### Apache 2.4

Ensure `mod_proxy`, `mod_proxy_http`, and `mod_ssl` are enabled:

```apache
<VirtualHost *:443>
    ServerName netcheck.example.com

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/netcheck.crt
    SSLCertificateKeyFile /etc/ssl/private/netcheck.key

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:7070/
    ProxyPassReverse / http://127.0.0.1:7070/

    # Pass client protocol and IP
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Port "443"
</VirtualHost>
```

---

## 4. Operational Lifecycle & Maintenance

### Inspection & Health Verification

```bash
# Verify container runtime status
docker ps --filter "name=netcheck"

# Query the internal health endpoint
curl -fsS http://127.0.0.1:7070/api/healthz

# View application logs (minimal output when ACCESS_LOG=0)
docker logs --tail 100 netcheck
```

### Performing Image Updates

#### Docker CLI:
```bash
docker pull nnt25/netcheck:latest
docker stop netcheck
docker rm netcheck
docker run -d \
  --name netcheck \
  --restart unless-stopped \
  -p 7070:7070 \
  -v netcheck-cache:/data/netcheck-cache \
  nnt25/netcheck:latest
```

#### Docker Compose:
```bash
docker compose pull
docker compose up -d --remove-orphans
```

### Clean Teardown

```bash
docker compose down -v
```

---

## 5. Security & Configuration References

- [SECURITY.md](./SECURITY.md) — Comprehensive threat model, SSRF gate definitions, and deployment topology matrix.
- [README.md](./README.md) — Full feature breakdown and complete REST API specifications.
