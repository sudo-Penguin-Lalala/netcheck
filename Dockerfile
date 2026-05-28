# NetCheck — single-stage image. python:3.11-slim + whois system bin.
# ping + traceroute are now remote-probe via Globalping; no local binaries needed.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Only whois (TCP 43 client) remains as a system tool. ping/traceroute have
# been replaced with Globalping API calls so the origin IP no longer touches
# the target — closes the "we can trace you back through Cloudflare" leak.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        whois \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first to leverage layer caching
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Application code
COPY backend /app/backend
COPY frontend /app/frontend

# Drop to a non-root user. No raw-socket capabilities required anymore since
# ping/traceroute are HTTPS calls to the Globalping API.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 1000 netcheck \
 && chown -R netcheck:netcheck /app
USER netcheck

EXPOSE 7070

# Healthcheck hits the JSON endpoint so the container is "unhealthy" if the app crashes
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7070/api/healthz', timeout=3).status == 200 else 1)" \
    || exit 1

# Default proxy-trust list. Safe for host-networking and Docker bridge
# deployments. Override via TRUSTED_PROXIES env in .env / compose for other
# topologies (see SECURITY.md). NEVER set this to "*" in production —
# trusting any source IP lets clients forge X-Forwarded-For and bypass the
# per-IP rate limiter.
ENV TRUSTED_PROXIES="127.0.0.1,172.16.0.0/12"

# Use shell-form so $TRUSTED_PROXIES expands at runtime, not build time.
CMD uvicorn backend.main:app --host 0.0.0.0 --port 7070 --proxy-headers --forwarded-allow-ips="$TRUSTED_PROXIES"
