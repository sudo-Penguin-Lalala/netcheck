"""POST /api/mtr — remote-probe MTR (My TraceRoute) via Globalping mtr type.

Combines traceroute hop discovery with per-hop loss / min / avg / max
latency in a single measurement. Origin-leak-free.
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


class MtrRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    location: str | None = Field(default=None, max_length=8)


def _f(v) -> float | None:
    return float(v) if isinstance(v, (int, float)) else None


def _normalize(body: dict, host: str) -> dict:
    results = body.get("results") or []
    if not results:
        return {"host": host, "hops": []}
    hops_raw = ((results[0].get("result") or {}).get("hops")) or []
    out: list[dict] = []
    for i, h in enumerate(hops_raw, start=1):
        ip = h.get("resolvedAddress") or None
        hostname = h.get("resolvedHostname") or None
        if hostname == ip:
            hostname = None
        stats = h.get("stats") or {}
        # Globalping mtr stats: {min, avg, max, total, rcv, drop, loss, stDev, jMin, jAvg, jMax}
        loss = _f(stats.get("loss"))
        if loss is None:
            sent = stats.get("total") or 0
            recv = stats.get("rcv") or 0
            loss = 0.0 if not sent else round((sent - recv) / sent * 100.0, 2)
        out.append({
            "n": i,
            "ip": ip,
            "hostname": hostname,
            "loss_pct": loss,
            "avg_ms": _f(stats.get("avg")),
            "best_ms": _f(stats.get("min")),
            "worst_ms": _f(stats.get("max")),
        })
    return {"host": host, "hops": out}


@router.post("/mtr", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def mtr_host(request: Request, body: MtrRequest):
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
        "type": "mtr",
        "limit": 1,
        "measurementOptions": {"protocol": "ICMP", "packets": 3},
    }
    locs = build_locations(body.location)
    if locs:
        payload["locations"] = locs

    try:
        result = await run_measurement(payload)
    except GlobalpingError as e:
        raise HTTPException(e.status, {"error": e.code, "message": e.message})

    return _normalize(result, host)
