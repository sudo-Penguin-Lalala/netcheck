# NetCheck Deployment Guide

This guide covers deploying NetCheck v2.0.0 in production behind common reverse proxies (Caddy, Nginx, Traefik, Apache) or on a bare-metal server.

---

## 1. Container Hardening Overview

NetCheck v2 runs as a single, statically compiled Go binary inside a bare `scratch` container. Because the application holds all state in memory (LRU caches and token-bucket limiters), the container requires no writable storage and no volume mounts.

Key deployment characteristics:
- **Port:** Defaults to `7070` (override via `PORT=7070`).
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
      - "127.0.0.1:7070:7070"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    environment:
      - PORT=7070
      # - AUTH_TOKEN=your-32-char-random-token-here
      # - ALLOW_PRIVATE_TARGETS=0
      # - TRUSTED_PROXIES=127.0.0.1,::1,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16
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
    reverse_proxy 127.0.0.1:7070 {
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
        proxy_pass         http://127.0.0.1:7070;
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
          - url: "http://127.0.0.1:7070"
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
    ProxyPass / http://127.0.0.1:7070/
    ProxyPassReverse / http://127.0.0.1:7070/

    # Allow long traceroute probe timeouts
    ProxyTimeout 60
</VirtualHost>
```

---

## 4. Cloudflare Deployment Patterns

### 4.1 Cloudflare Tunnel (`cloudflared`) — Recommended

When using Cloudflare Tunnel, no inbound ports need to be opened on your firewall or router. The `cloudflared` daemon runs locally and establishes outbound connections to Cloudflare's edge.

Because `cloudflared` proxies HTTP requests to NetCheck **locally**, the incoming TCP connection to NetCheck originates from `127.0.0.1`, `::1`, or Docker's internal bridge network (`172.16.0.0/12`), **not** from Cloudflare's public IP addresses.

Cloudflare automatically passes the visitor's real IP via the `CF-Connecting-IP` header. To ensure NetCheck trusts this header and displays the visitor's connection info (rather than falling back to the server host IP), set:

```env
TRUSTED_PROXIES=127.0.0.1,::1,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16
```

*(If `TRUSTED_PROXIES` is left unset, NetCheck defaults to trusting these standard private and loopback ranges).*

#### Pattern A: NetCheck behind an existing host `cloudflared`

Use this if `cloudflared` is already installed as a systemd service or running outside this Compose file:

```yaml
services:
  netcheck:
    image: nnt25/netcheck:latest
    container_name: netcheck
    restart: unless-stopped
    ports:
      # Bind to 127.0.0.1 so only local processes (cloudflared) can access port 7070
      - "127.0.0.1:7070:7070"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    environment:
      - PORT=7070
      - TRUSTED_PROXIES=127.0.0.1,::1,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16
      - ALLOW_PRIVATE_TARGETS=0
      # - GLOBALPING_TOKEN=your-token
```

In your Cloudflare Zero Trust dashboard or `config.yml`, route the public hostname to:
```
http://localhost:7070
```

#### Pattern B: All-in-One Compose (NetCheck + `cloudflared` Sidecar)

Use this if you want `cloudflared` to run in the same `docker-compose.yml`:

```yaml
services:
  netcheck:
    image: nnt25/netcheck:latest
    container_name: netcheck
    restart: unless-stopped
    expose:
      - "7070"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    environment:
      - PORT=7070
      - TRUSTED_PROXIES=127.0.0.1,::1,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16
      - ALLOW_PRIVATE_TARGETS=0
      # - GLOBALPING_TOKEN=your-token

  tunnel:
    image: cloudflare/cloudflared:latest
    container_name: cloudflared
    restart: unless-stopped
    command: tunnel run
    environment:
      - TUNNEL_TOKEN=eyJh...your-tunnel-token-here...
```

In your Cloudflare Zero Trust dashboard, set the service URL for the tunnel to:
```
http://netcheck:7070
```

---

### 4.2 Cloudflare CDN (Direct Public Origin with Proxied DNS 🟧)

Only use this pattern if your server exposes public ports (e.g., port 443 with Nginx/Caddy) directly to the public internet, and traffic is routed through Cloudflare's public edge proxies.

In this setup, the direct TCP peer connecting to your server is one of Cloudflare's public edge IPs. Configure NetCheck to trust Cloudflare's published IP ranges:

```env
TRUSTED_PROXIES=173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22
```

Direct clients connecting outside Cloudflare will have any spoofed `CF-Connecting-IP` or `X-Forwarded-For` headers ignored.

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
   Environment=PORT=7070
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
curl -s http://127.0.0.1:7070/api/healthz
# Returns: {"status":"ok","version":"2.0.0","auth_required":false}
```
