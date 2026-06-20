# syntax=docker/dockerfile:1
# NetCheck — single-stage image. python:3.11-slim + whois system bin.
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

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
       whois \
       ca-certificates \
&& rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY frontend /app/frontend

RUN useradd --no-log-init --create-home --shell /usr/sbin/nologin --uid 1000 netcheck \
&& chown -R netcheck:netcheck /app
USER netcheck

EXPOSE 7070

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
   CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7070/api/healthz', timeout=3).status == 200 else 1)" \
   || exit 1

ENV TRUSTED_PROXIES="127.0.0.1,172.16.0.0/12"

# Shell-form intentional: $TRUSTED_PROXIES must expand at runtime, not build time.
# hadolint ignore=DL3025
CMD uvicorn backend.main:app --host 0.0.0.0 --port 7070 --proxy-headers --forwarded-allow-ips="$TRUSTED_PROXIES"
