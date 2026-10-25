"""GET /api/ip — public IP + GeoIP with resilient multi-tier failover (ipwho.is -> ip-api.com)."""
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


async def _fetch_ip_info(client_ip: str) -> dict:
    cli = get_http_client()
    target = client_ip if client_ip and not is_private_ip(client_ip) else ""

    # Tier 1: ipwho.is (HTTPS, free, 10k/month)
    url_ipwho = f"https://ipwho.is/{target}" if target else "https://ipwho.is/"
    try:
        resp = await cli.get(url_ipwho, headers={"Accept": "application/json"}, timeout=_IP_API_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success", False):
                conn = data.get("connection") or {}
                asn = conn.get("asn")
                org = conn.get("org") or ""
                isp = conn.get("isp") or org or ""
                asn_str = f"AS{asn}" if asn else ""
                if asn_str and org:
                    asn_str = f"{asn_str} ({org})"
                return {
                    "ip": data.get("ip") or client_ip,
                    "isp": isp,
                    "asn": asn_str,
                    "org": org,
                    "country": data.get("country") or "",
                    "city": data.get("city") or "",
                }
    except (httpx.HTTPError, ValueError):
        pass

    # Tier 2 Fallback: ip-api.com (free 45/min, high availability)
    url_ipapi = (
        f"http://ip-api.com/json/{target}?fields=status,message,query,isp,as,org,country,city"
        if target
        else "http://ip-api.com/json/?fields=status,message,query,isp,as,org,country,city"
    )
    try:
        resp = await cli.get(url_ipapi, timeout=_IP_API_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                asn_raw = data.get("as") or ""
                org = data.get("org") or ""
                isp = data.get("isp") or org or ""
                return {
                    "ip": data.get("query") or client_ip,
                    "isp": isp,
                    "asn": asn_raw,
                    "org": org,
                    "country": data.get("country") or "",
                    "city": data.get("city") or "",
                }
    except (httpx.HTTPError, ValueError):
        pass

    return {}


@router.get("/ip", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def get_ip(request: Request):
    client = _client_ip(request)
    result = await _fetch_ip_info(client)

    if not result:
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream_failure", "message": "All IP lookup upstreams failed to respond"},
        )

    return result
