# NetCheck Deployment Guide

This guide covers deploying NetCheck v2.0.0 in production behind common reverse proxies (Caddy, Nginx, Traefik, Apache) or on a bare-metal server.

---

## 1. Container Hardening Overview

NetCheck v2 runs as a single, statically compiled Go binary inside a bare `scratch` container. Because the application holds all state in memory (LRU caches and token-bucket limiters), the container requires no writable storage and no volume mounts.

Key deployment characteristics:
- **Port:** Defaults to `8000` (override via `PORT=8000`).
- **Filesystem:** Run with `read_only: true`. The binary needs no scratch space or temporary directories on disk.
- **Capabilities:** Drop everything (`cap_drop: [ALL]`). Probes execute over standard TCP/UDP and HTTP sockets; raw socket capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`) are unnecessary.
- **User:** Runs as unprivileged user `10001` (configured in the scratch container's `/etc/passwd`).
- **Health Check:** `GET /api/healthz` returns JSON with status code `200` (`{"status":"ok","version":"2.0.0","auth_required":...}`).

---

## 2. Production Docker Compose

Save this configuration as `docker-compose.yml`:

```yaml
services:
  netcheck:
    image: nnt25/netcheck:latest
    container_name: netcheck
    restart: unless-stopped
    ports:
      # Bind to 127.0.0.1 so the container is only reachable through your reverse proxy
      - "127.0.0.1:8000:8000"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    environment:
      - PORT=8000
      # - AUTH_TOKEN=your-32-char-random-token-here
      # - ALLOW_PRIVATE_TARGETS=0
      # - TRUSTED_PROXIES=127.0.0.1,172.16.0.0/12,10.0.0.0/8
      # - GLOBALPING_TOKEN=your-token-from-globalping
      # - ALLOWED_ORIGINS=https://netcheck.example.com
```

Start the service:

```bash
docker compose up -d
```

---

## 3. Reverse Proxy Setups

Always pair NetCheck with a TLS-terminating reverse proxy when exposing it to the internet. Make sure your proxy passes `Host`, `X-Real-IP`, and `X-Forwarded-For` so the rate limiter and client IP tools work accurately.

### Caddy (Recommended)

Caddy handles automatic HTTPS provisioning and certificate renewals out of the box:

```caddyfile
netcheck.example.com {
    reverse_proxy 127.0.0.1:8000 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
    }
}
```

*Required Environment:* Set `TRUSTED_PROXIES=127.0.0.1` in NetCheck so it trusts Caddy's forwarded headers.

---

### Nginx

Standard Nginx virtual host with HTTP/2 and extended read timeouts for deep traceroutes:

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name netcheck.example.com;

    ssl_certificate     /etc/ssl/certs/netcheck.crt;
    ssl_certificate_key /etc/ssl/private/netcheck.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_http_version 1.1;

        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Traceroutes and deep MTRs can take up to 35 seconds to finish
        proxy_read_timeout 60s;
        proxy_connect_timeout 10s;
    }
}
```

*Required Environment:* Set `TRUSTED_PROXIES=127.0.0.1`.

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
          - url: "http://127.0.0.1:8000"
```

---

### Apache 2.4

Make sure `mod_proxy`, `mod_proxy_http`, and `mod_ssl` are enabled:

```apache
<VirtualHost *:443>
    ServerName netcheck.example.com

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/netcheck.crt
    SSLCertificateKeyFile /etc/ssl/private/netcheck.key

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/

    # Allow long traceroute probe timeouts
    ProxyTimeout 60
</VirtualHost>
```

---

## 4. Cloudflare CDN / Tunnel Notes

If you run NetCheck behind Cloudflare CDN or Cloudflare Tunnel:
1. Set `TRUSTED_PROXIES` to Cloudflare's published IP ranges so NetCheck knows to extract the true visitor IP from `CF-Connecting-IP`:
   ```env
   TRUSTED_PROXIES=173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22
   ```
2. Any client connecting directly to your origin server (skipping Cloudflare) will have its fake headers ignored; NetCheck will rate-limit and log the direct peer socket IP instead.

---

## 5. Systemd Service (Bare Metal / No Docker)

If you prefer running without containers:

1. Build the binary:
   ```bash
   CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /usr/local/bin/netcheck .
   ```
2. Create an unprivileged user:
   ```bash
   useradd -r -s /bin/false -U netcheck
   ```
3. Save `/etc/systemd/system/netcheck.service`:
   ```ini
   [Unit]
   Description=NetCheck Network Diagnostic Service
   After=network.target

   [Service]
   Type=simple
   User=netcheck
   Group=netcheck
   Environment=PORT=8000
   Environment=ALLOW_PRIVATE_TARGETS=0
   Environment=TRUSTED_PROXIES=127.0.0.1
   ExecStart=/usr/local/bin/netcheck
   Restart=always
   RestartSec=5
   LimitNOFILE=65535

   # Security Sandboxing
   ProtectSystem=strict
   ProtectHome=true
   NoNewPrivileges=true
   PrivateTmp=true

   [Install]
   WantedBy=multi-user.target
   ```
4. Enable and start:
   ```bash
   systemctl daemon-reload
   systemctl enable --now netcheck
   ```

---

## 6. Upgrades & Maintenance

Upgrading NetCheck v2 is completely painless because there is no database migration or disk state to preserve:

```bash
# Pull the latest image and recreate the container
docker compose pull
docker compose up -d --remove-orphans
```

To verify the updated version:
```bash
curl -s http://127.0.0.1:8000/api/healthz
# Returns: {"status":"ok","version":"2.0.0","auth_required":false}
```
