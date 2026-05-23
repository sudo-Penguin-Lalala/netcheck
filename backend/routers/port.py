"""POST /api/port — remote-probe TCP reachability via Globalping http measurement.

Origin-leak fix: previously opened raw TCP sockets from this server's IP.
Globalping runs the connect from a third-party probe, so target only sees
the probe's address.

Globalping has no plain TCP-only measurement — `http` is the closest
primitive. We interpret `timings.tcp` (ms) as proof TCP completed, regardless
of whether the higher-level HTTP request succeeded. This covers non-HTTP
ports (SSH, SMTP, MySQL, etc.) correctly: TCP handshake completes, HTTP
parse fails, but the port is still classified `open`.
"""
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

# Use HTTPS hint only on canonical TLS ports so the probe attempts a TLS
# handshake. For everything else (22/25/3306/etc.) we use HTTP — the probe
# will still complete TCP, then fail at the HTTP layer, which is fine.
_TLS_PORTS = {443, 465, 563, 636, 989, 990, 992, 993, 994, 995, 8443, 9443}


class PortRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    timeout: float = Field(default=3.0, ge=0.1, le=10.0)  # accepted for compat; Globalping has its own
    location: str | None = Field(default=None, max_length=8)


def _classify(body: dict) -> str:
    results = body.get("results") or []
    if not results:
        return "closed"
    res = results[0].get("result") or {}
    timings = res.get("timings") or {}
    tcp = timings.get("tcp")
    if isinstance(tcp, (int, float)) and tcp >= 0:
        return "open"
    raw = (res.get("rawOutput") or "").lower()
    # Non-HTTP servers (SSH/SMTP/MySQL) accept TCP then drop the HTTP request.
    # Globalping reports these without a tcp timing but with a tell-tale string.
    open_signals = (
        "other side closed",
        "socket hang up",
        "premature close",
        "econnreset",
        "epipe",
        "parse error",
        "invalid http",
        "does not match the http",
        "expected http/",
    )
    if any(s in raw for s in open_signals):
        return "open"
    if "etimedout" in raw or "timed out" in raw or "timeout" in raw:
        return "timeout"
    if "econnrefused" in raw or "connection refused" in raw or "refused" in raw:
        return "closed"
    if "enotfound" in raw or "getaddrinfo" in raw:
        return "closed"
    return "closed"


@router.post("/port", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def port_check(request: Request, body: PortRequest):
    host = body.host.strip().lower()

    if not is_valid_host_or_ip(host):
        raise HTTPException(400, {"error": "bad_input", "message": "Invalid host or IP"})
    if is_private_target_blocked(host):
        raise HTTPException(
            403,
            {
                "error": "private_blocked",
                "message": "Private/loopback targets cannot be measured by remote probes.",
            },
        )

    protocol = "HTTPS" if body.port in _TLS_PORTS else "HTTP"
    payload = {
        "target": host,
        "type": "http",
        "limit": 1,
        "measurementOptions": {
            "port": body.port,
            "protocol": protocol,
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

    return {"host": host, "port": body.port, "status": _classify(result)}
