"""POST /api/http — remote-probe HTTP request via Globalping http measurement.

Parses the supplied URL into host / port / scheme / path, submits a single
HTTP request from a Globalping probe, then surfaces status, timing,
redirects (Location header for 3xx), key headers, and TLS validity.

Origin-leak-free: the request originates from the probe, not our server.
"""
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.utils.globalping import GlobalpingError, build_locations, run_measurement
from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import (
    is_private_target_blocked,
    is_valid_host_or_ip,
    require_auth,
)

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
        raise HTTPException(400, {"error": "bad_input", "message": "Only http/https URLs supported"})
    host = (p.hostname or "").strip().lower()
    if not host:
        raise HTTPException(400, {"error": "bad_input", "message": "URL has no host"})
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
        raise HTTPException(400, {"error": "bad_input", "message": "Invalid host in URL"})
    if is_private_target_blocked(host):
        raise HTTPException(
            403,
            {
                "error": "private_blocked",
                "message": "Private/loopback targets cannot be measured by remote probes.",
            },
        )

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
