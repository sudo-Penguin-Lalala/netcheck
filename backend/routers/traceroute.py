"""POST /api/traceroute — remote-probe traceroute via Globalping API.

Origin-leak fix: previously ran subprocess `traceroute`/`tracepath`, which
sent ICMP/UDP probes from this server's IP — exposing origin to the target
even when fronted by Cloudflare (which only proxies TCP 80/443). Globalping
runs the trace from a third-party probe; origin IP never touches target.
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


class TraceRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    max_hops: int = Field(default=30, ge=1, le=64)  # accepted for API compat; Globalping uses its own limit
    location: str | None = Field(default=None, max_length=8)


def _normalize(body: dict) -> list[dict]:
    """Flatten Globalping traceroute → existing {n,ip,hostname,latency_ms} shape."""
    results = body.get("results") or []
    if not results:
        return []
    hops_raw = ((results[0].get("result") or {}).get("hops")) or []
    out: list[dict] = []
    for i, h in enumerate(hops_raw, start=1):
        ip = h.get("resolvedAddress") or None
        hostname = h.get("resolvedHostname") or None
        if hostname == ip:
            hostname = None
        timings = h.get("timings") or []
        rtts = [t.get("rtt") for t in timings if isinstance(t.get("rtt"), (int, float))]
        latency = round(min(rtts), 3) if rtts else None
        out.append({"n": i, "ip": ip, "hostname": hostname, "latency_ms": latency})
    return out


@router.post("/traceroute", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def traceroute_host(request: Request, body: TraceRequest):
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

    payload = {
        "target": host,
        "type": "traceroute",
        "limit": 1,
        "measurementOptions": {"protocol": "ICMP"},
    }
    locs = build_locations(body.location)
    if locs:
        payload["locations"] = locs

    try:
        result = await run_measurement(payload)
    except GlobalpingError as e:
        raise HTTPException(e.status, {"error": e.code, "message": e.message})

    return {"hops": _normalize(result)}
