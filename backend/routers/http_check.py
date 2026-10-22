"""POST /api/http — remote-probe HTTP request via Globalping http measurement.

Parses the supplied URL into host / port / scheme / path, submits a single
HTTP request from a Globalping probe, then surfaces status, timing,
redirects (Location header for 3xx), key headers, and TLS validity.

Origin-leak-free: the request originates from the probe, not our server.
"""
import logging
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.utils.globalping import GlobalpingError, build_locations, run_measurement
from backend.utils.http_client import get_http_client
from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import (
    is_private_ip,
    is_private_target_blocked,
    is_valid_host_or_ip,
    require_auth,
)

log = logging.getLogger(__name__)
router = APIRouter()

_INTERESTING_HEADERS = {
    "content-type",
    "content-length",
    "server",
    "location",
    "cache-control",
    "content-encoding",
    "x-powered-by",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "set-cookie",
    "cf-ray",
}


class HttpRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    location: str | None = Field(default=None, max_length=8)


def _parse_url(url: str) -> tuple[str, int, str, str]:
    """→ (host, port, scheme:HTTP|HTTPS, path)."""
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    scheme = (p.scheme or "https").lower()
    if scheme not in ("http", "https"):
        raise HTTPException(400, {"error": "bad_input", "message": "Unsupported protocol: Target URL must begin with http:// or https://"})
    host = (p.hostname or "").strip().lower()
    if not host:
        raise HTTPException(400, {"error": "bad_input", "message": "Malformed URL: Missing host component (e.g. https://example.com/path)"})
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path = f"{path}?{p.query}"
    return host, port, "HTTPS" if scheme == "https" else "HTTP", path


def _filter_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    if not headers or not isinstance(headers, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in _INTERESTING_HEADERS:
            out[k] = ", ".join(v) if isinstance(v, list) else str(v)
    return out


@router.post("/http", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def http_check(request: Request, body: HttpRequest):
    url = body.url.strip()
    host, port, protocol, path = _parse_url(url)

    if not is_valid_host_or_ip(host):
        raise HTTPException(400, {"error": "bad_input", "message": "Invalid target host in URL: Must be a valid FQDN or IP address"})
    if await is_private_target_blocked(host):
        raise HTTPException(
            403,
            {
                "error": "private_blocked",
                "message": f"RFC 1918 Forbidden: Remote probes cannot route to private/loopback IP ({host}). Set ALLOW_PRIVATE_TARGETS=1 for local execution.",
            },
        )

    # Native local HTTP check for allowed private/homelab targets
    if is_private_ip(host):
        client = get_http_client()
        start_t = time.perf_counter()
        target_url = f"{protocol.lower()}://{host}:{port}{path}"
        try:
            try:
                resp = await client.request(
                    "GET",
                    target_url,
                    follow_redirects=False,
                    timeout=10.0,
                )
                tls_valid = True
            except httpx.ConnectError:
                # If HTTPS failed (e.g. self-signed cert on homelab router), retry with verify=False
                if protocol == "HTTPS":
                    async with httpx.AsyncClient(verify=False, timeout=10.0) as insecure_client:
                        resp = await insecure_client.request(
                            "GET",
                            target_url,
                            follow_redirects=False,
                        )
                    tls_valid = False
                else:
                    raise

            elapsed_ms = int((time.perf_counter() - start_t) * 1000)
            headers = _filter_headers(dict(resp.headers))
            redirects: list[str] = []
            if 300 <= resp.status_code < 400:
                loc = headers.get("location") or headers.get("Location")
                if loc:
                    redirects.append(loc)

            tls_payload = {"valid": tls_valid, "days_remaining": None} if protocol == "HTTPS" else None

            return {
                "url": url,
                "status_code": resp.status_code,
                "status_text": resp.reason_phrase or "",
                "response_time_ms": elapsed_ms,
                "redirects": redirects,
                "headers": headers,
                "tls": tls_payload,
            }
        except Exception as e:
            log.warning("Local HTTP check failed for %s: %s", host, e)
            elapsed_ms = int((time.perf_counter() - start_t) * 1000)
            return {
                "url": url,
                "status_code": None,
                "status_text": "Connection failed (TCP handshake refused, TLS error, or DNS lookup failure)",
                "response_time_ms": elapsed_ms,
                "redirects": [],
                "headers": {},
                "tls": None,
            }

    payload: dict[str, Any] = {
        "target": host,
        "type": "http",
        "limit": 1,
        "measurementOptions": {
            "port": port,
            "protocol": protocol,
            "request": {"path": path, "method": "GET"},
        },
    }
    locs = build_locations(body.location)
    if locs:
        payload["locations"] = locs

    try:
        result = await run_measurement(payload)
    except GlobalpingError as e:
        raise HTTPException(e.status, {"error": e.code, "message": e.message})

    results = result.get("results") or []
    if not results:
        raise HTTPException(502, {"error": "no_result", "message": "Probe returned no result"})

    res = results[0].get("result") or {}
    status_code = res.get("statusCode")
    status_text = res.get("statusCodeName") or ""
    timings = res.get("timings") or {}
    total_ms = timings.get("total")
    headers = _filter_headers(res.get("headers"))

    redirects: list[str] = []
    if status_code and 300 <= int(status_code) < 400:
        loc = headers.get("location") or headers.get("Location")
        if loc:
            redirects.append(loc)

    tls_block = res.get("tls") or {}
    tls_payload: dict[str, Any] | None = None
    if tls_block:
        import datetime as _dt
        valid_until = tls_block.get("expiresAt")
        days_remaining = None
        if valid_until:
            try:
                exp = _dt.datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
                days_remaining = (exp - _dt.datetime.now(_dt.timezone.utc)).days
            except ValueError:
                pass
        tls_payload = {
            "valid": bool(tls_block.get("authorized")),
            "days_remaining": days_remaining,
        }

    return {
        "url": url,
        "status_code": status_code,
        "status_text": status_text,
        "response_time_ms": int(total_ms) if isinstance(total_ms, (int, float)) else None,
        "redirects": redirects,
        "headers": headers,
        "tls": tls_payload,
    }
