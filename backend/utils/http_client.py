"""Shared lifespan-managed HTTP connection pool.

Reuses persistent HTTP/2 and HTTP/1.1 connections across endpoints (GeoIP,
IP lookup, Globalping API) to avoid redundant TCP and TLS handshake overhead.
"""
import httpx

_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    """Return the shared singleton AsyncClient. Creates on demand if needed."""
    global _client
    if _client is None or _client.is_closed:
        limits = httpx.Limits(
            max_keepalive_connections=20,
            max_connections=50,
            keepalive_expiry=30.0,
        )
        timeout = httpx.Timeout(15.0, connect=5.0)
        _client = httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            http2=False,  # http2=False ensures max compatibility with all third-party APIs
            headers={"User-Agent": "NetCheck/1.4 (+https://github.com/sudo-Penguin-Lalala/netcheck)"},
        )
    return _client


async def close_http_client() -> None:
    """Close the shared HTTP client gracefully during server shutdown."""
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
        _client = None
