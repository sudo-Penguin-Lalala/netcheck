# syntax=docker/dockerfile:1
# NetCheck — optimized single-stage image. python:3.11-slim + whois system bin.
# ping + traceroute are now remote-probe via Globalping; no local binaries needed.
FROM python:3.11-slim

LABEL org.opencontainers.image.title="NetCheck" \
     org.opencontainers.image.description="Self-hosted network diagnostic toolkit" \
     org.opencontainers.image.url="https://netcheck.nnt25.io.vn" \
     org.opencontainers.image.source="https://github.com/sudo-Penguin-Lalala/netcheck" \
     org.opencontainers.image.licenses="AGPL-3.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
   PYTHONUNBUFFERED=1 \
   PIP_NO_CACHE_DIR=1 \
   PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies in single layer
RUN apt-get update \
&& apt-get install -y --no-install-recommends \
       whois \
       ca-certificates \
       gosu \
&& apt-get clean \
&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt \
&& find /usr/local -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# Copy application code
COPY backend /app/backend
COPY frontend /app/frontend

# Create non-root user with strict permissions
RUN useradd --no-log-init --create-home --shell /usr/sbin/nologin --uid 1000 netcheck \
&& chown -R netcheck:netcheck /app \
&& chmod 755 /app \
&& chmod -R 755 /app/backend /app/frontend

# Copy and setup entrypoint
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 7070

# Optimized healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
   CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7070/api/healthz', timeout=3).status == 200 else 1)" \
   || exit 1

ENV TRUSTED_PROXIES="127.0.0.1,172.16.0.0/12" \
    ACCESS_LOG="0"

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Shell-form intentional: $TRUSTED_PROXIES must expand at runtime, not build time.
# Single worker: in-memory rate limiter is per-process. For multi-replica deploys,
# set REDIS_URL to share rate-limit state across workers/pods.
# hadolint ignore=DL3025
CMD if [ "$ACCESS_LOG" = "0" ]; then \
        uvicorn backend.main:app --host 0.0.0.0 --port 7070 --workers 1 --proxy-headers --forwarded-allow-ips="$TRUSTED_PROXIES" --no-access-log; \
    else \
        uvicorn backend.main:app --host 0.0.0.0 --port 7070 --workers 1 --proxy-headers --forwarded-allow-ips="$TRUSTED_PROXIES"; \
    fi
