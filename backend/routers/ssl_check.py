"""POST /api/ssl — inspect a TLS peer cert via Globalping http measurement.

Origin-leak fix: previously did an in-process TLS handshake from this
server's IP. Globalping runs the handshake from a third-party probe; the
target sees only the probe.

Globalping inspects certs even when the chain is invalid (expired, wrong
hostname, self-signed) — `tls.authorized:false` is set but all cert metadata
is still populated, matching the previous CERT_NONE behavior of the
subprocess implementation.
"""
import datetime
from typing import Any

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


class SslRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)
    timeout: float = Field(default=5.0, ge=0.5, le=10.0)  # accepted for compat
    location: str | None = Field(default=None, max_length=8)


def _parse_san(alt: str | None) -> list[str]:
    """Globalping returns SAN as a single string like
    'DNS:example.com, DNS:*.example.com, IP Address:1.2.3.4' — split + strip prefixes.
    """
    if not alt:
        return []
    out: list[str] = []
    for token in alt.split(","):
        t = token.strip()
        if t.startswith("DNS:"):
            out.append(t[4:])
        elif t.startswith("IP Address:"):
            out.append(t[11:].strip())
        elif t:
            out.append(t)
    return out


def _parse_iso(s: str | None) -> datetime.datetime | None:
    if not s:
        return None
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


def _build_response(host: str, port: int, tls: dict[str, Any]) -> dict[str, Any]:
    subject = tls.get("subject") or {}
    issuer = tls.get("issuer") or {}

    valid_from = _parse_iso(tls.get("createdAt"))
    valid_until = _parse_iso(tls.get("expiresAt"))
    now = datetime.datetime.now(datetime.timezone.utc)
    days_remaining = (valid_until - now).days if valid_until else 0
    expired = bool(valid_until and valid_until < now)

    return {
        "host": host,
        "port": port,
        "subject": {"commonName": subject.get("CN") or ""},
        "issuer": {
            "organizationName": (
                issuer.get("O") or issuer.get("CN") or issuer.get("OU") or ""
            )
        },
        "valid_from": valid_from.isoformat() if valid_from else "",
        "valid_until": valid_until.isoformat() if valid_until else "",
        "days_remaining": days_remaining,
        "expired": expired,
        "san": _parse_san(subject.get("alt")),
    }


@router.post("/ssl", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def ssl_check(request: Request, body: SslRequest):
    host = body.host.strip().lower()

    if not is_valid_host_or_ip(host):
        raise HTTPException(400, {"error": "bad_input", "message": "Invalid host"})
    if is_private_target_blocked(host):
        raise HTTPException(
            403,
            {
                "error": "private_blocked",
                "message": "Private/loopback targets cannot be measured by remote probes.",
            },
        )

    payload = {
        "target": host,
        "type": "http",
        "limit": 1,
        "measurementOptions": {
            "port": body.port,
            "protocol": "HTTPS",
            "request": {"path": "/", "method": "HEAD"},
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
    tls = res.get("tls")
    if not tls:
        raw = (res.get("rawOutput") or "").strip()
        msg = "TLS handshake failed or port did not negotiate TLS"
        if raw:
            msg = f"{msg}: {raw[:200]}"
        raise HTTPException(502, {"error": "tls_error", "message": msg})

    return _build_response(host, body.port, tls)
