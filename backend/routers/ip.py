"""GET /api/ip — public IP + GeoIP via ip-api.com (free, no key)."""
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import is_private_ip, is_valid_ip, require_auth

router = APIRouter()
_IP_API_TIMEOUT = 5.0
_FIELDS = "status,message,query,isp,as,country,city"


def _client_ip(request: Request) -> str:
    # Prefer X-Forwarded-For (homelab users behind reverse proxies need this)
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        first = xff.split(",")[0].strip()
        if is_valid_ip(first):
            return first
    real = request.headers.get("X-Real-IP", "").strip()
    if real and is_valid_ip(real):
        return real
    if request.client:
        return request.client.host
    return ""


@router.get("/ip", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def get_ip(request: Request):
    client = _client_ip(request)
    # If we can't see a public client IP, let ip-api detect the server's egress IP
    if not client or is_private_ip(client):
        url = f"http://ip-api.com/json/?fields={_FIELDS}"
    else:
        url = f"http://ip-api.com/json/{client}?fields={_FIELDS}"

    try:
        async with httpx.AsyncClient(timeout=_IP_API_TIMEOUT) as cli:
            resp = await cli.get(url)
            resp.raise_for_status()
            data = resp.json()
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail={"error": "timeout", "message": "IP lookup upstream timed out"},
        )
    except (httpx.HTTPError, ValueError):
        raise HTTPException(
            status_code=500,
            detail={"error": "upstream_failure", "message": "IP lookup upstream returned invalid data"},
        )

    if data.get("status") != "success":
        raise HTTPException(
            status_code=500,
            detail={"error": "upstream_failure", "message": data.get("message", "IP lookup failed")},
        )

    return {
        "ip": data.get("query") or client,
        "isp": data.get("isp") or "",
        "asn": data.get("as") or "",
        "country": data.get("country") or "",
        "city": data.get("city") or "",
    }
