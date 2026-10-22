"""POST /api/ping — remote-probe ICMP ping via Globalping API.

Origin-leak fix: previously used subprocess `ping`, sending ICMP from this
server's IP. Globalping runs ping from a third-party probe, so the target
never sees our origin address.
"""
import asyncio
import re
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.utils.globalping import GlobalpingError, build_locations, run_measurement
from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import (
    is_private_ip,
    is_private_target_blocked,
    is_valid_host_or_ip,
    require_auth,
)

router = APIRouter()


class PingRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    count: int = Field(default=4, ge=1, le=10)
    location: str | None = Field(default=None, max_length=8)


def _normalize(body: dict, host: str) -> dict:
    """Globalping ping → existing {host, packets_sent, packets_recv, loss_pct, min/avg/max, raw}."""
    results = body.get("results") or []
    if not results:
        return {
            "host": host,
            "packets_sent": 0,
            "packets_recv": 0,
            "loss_pct": 100.0,
            "min": 0.0,
            "avg": 0.0,
            "max": 0.0,
            "raw": "no probe results",
        }
    res = results[0].get("result") or {}
    stats = res.get("stats") or {}
    sent = int(stats.get("total") or 0)
    recv = int(stats.get("rcv") or 0)
    loss = stats.get("loss")
    loss_pct = float(loss) if isinstance(loss, (int, float)) else (
        0.0 if sent == 0 else round((sent - recv) / sent * 100.0, 2)
    )
    return {
        "host": host,
        "packets_sent": sent,
        "packets_recv": recv,
        "loss_pct": loss_pct,
        "min": float(stats.get("min") or 0.0),
        "avg": float(stats.get("avg") or 0.0),
        "max": float(stats.get("max") or 0.0),
        "raw": (res.get("rawOutput") or "").strip(),
    }


@router.post("/ping", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def ping_host(request: Request, body: PingRequest):
    host = body.host.strip().lower()

    if not is_valid_host_or_ip(host):
        raise HTTPException(400, {"error": "bad_input", "message": "Invalid target: Must be a valid IPv4, IPv6, or FQDN"})
    if await is_private_target_blocked(host):
        raise HTTPException(
            403,
            {
                "error": "private_blocked",
                "message": f"RFC 1918 Forbidden: Remote probes cannot route to private/loopback IP ({host}). Set ALLOW_PRIVATE_TARGETS=1 for local execution.",
            },
        )

    # Native local ICMP ping execution for allowed private/homelab targets
    if is_private_ip(host):
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", str(body.count), "-W", "1", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=body.count * 1.5 + 2.0)
            raw = stdout.decode("utf-8", errors="replace").strip()
            sent = body.count
            recv = 0
            min_rtt = avg_rtt = max_rtt = 0.0
            m_stat = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received", raw)
            if m_stat:
                sent = int(m_stat.group(1))
                recv = int(m_stat.group(2))
            m_rtt = re.search(r"(?:rtt|round-trip)\s+min/avg/max/\S+\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)", raw)
            if m_rtt:
                min_rtt = float(m_rtt.group(1))
                avg_rtt = float(m_rtt.group(2))
                max_rtt = float(m_rtt.group(3))
            loss_pct = round((sent - recv) / sent * 100.0, 2) if sent > 0 else 100.0
            return {
                "host": host,
                "packets_sent": sent,
                "packets_recv": recv,
                "loss_pct": loss_pct,
                "min": min_rtt,
                "avg": avg_rtt,
                "max": max_rtt,
                "raw": raw,
            }
        except (FileNotFoundError, OSError, asyncio.TimeoutError):
            pass

    payload = {
        "target": host,
        "type": "ping",
        "limit": 1,
        "measurementOptions": {"packets": body.count},
    }
    locs = build_locations(body.location)
    if locs:
        payload["locations"] = locs

    try:
        result = await run_measurement(payload)
    except GlobalpingError as e:
        raise HTTPException(e.status, {"error": e.code, "message": e.message})

    return _normalize(result, host)
