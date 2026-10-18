"""GET /api/ip — public IP + GeoIP via ipwho.is (HTTPS, free, no key)."""
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

from backend.utils.http_client import get_http_client
from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import is_private_ip, is_valid_ip, require_auth

router = APIRouter()
_IP_API_TIMEOUT = 5.0


def _client_ip(request: Request) -> str:
    # Rely on request.client.host which Uvicorn already resolves and filters
    # using --forwarded-allow-ips="$TRUSTED_PROXIES". Never trust raw XFF.
    if request.client and request.client.host:
        host = request.client.host.strip()
        if is_valid_ip(host):
            return host
    return ""


@router.get("/ip", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def get_ip(request: Request):
    client = _client_ip(request)
    # If client is private/loopback or missing, query server's public egress IP
    if not client or is_private_ip(client):
        url = "https://ipwho.is/"
    else:
        url = f"https://ipwho.is/{client}"

    cli = get_http_client()
    try:
        resp = await cli.get(url, headers={"Accept": "application/json"}, timeout=_IP_API_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail={"error": "timeout", "message": "IP lookup upstream timed out"},
        )
    except (httpx.HTTPError, ValueError):
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream_failure", "message": "IP lookup upstream returned invalid data"},
        )

    if not data.get("success", False):
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream_failure", "message": data.get("message", "IP lookup failed")},
        )

    conn = data.get("connection") or {}
    asn = conn.get("asn")
    org = conn.get("org") or ""
    isp = conn.get("isp") or org or ""
    asn_str = f"AS{asn}" if asn else ""
    if asn_str and org:
        asn_str = f"{asn_str} ({org})"

    return {
        "ip": data.get("ip") or client,
        "isp": isp,
        "asn": asn_str,
        "org": org,
        "country": data.get("country") or "",
        "city": data.get("city") or "",
    }
