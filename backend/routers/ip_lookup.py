"""GET /api/ip-lookup — detailed IP/GeoIP via ipwhois.io."""
import os
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query

from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import is_private_ip, is_valid_ip, require_auth

router = APIRouter()
_TIMEOUT = 10.0

@router.get("/ip-lookup", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def ip_lookup(ip: str = Query(..., min_length=7)):
    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail={"error": "bad_input", "message": "Invalid IP address"})
    
    if is_private_ip(ip):
         raise HTTPException(status_code=400, detail={"error": "forbidden", "message": "Private/loopback IPs are not allowed"})

    api_key = os.environ.get("IPWHOIS_API_KEY", "").strip()
    
    # ipwhois.io uses different domains for free vs pro
    if api_key:
        url = f"https://ipwhois.pro/{ip}?key={api_key}"
    else:
        url = f"https://ipwho.is/{ip}"

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url)
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

    # ipwhois.io success field is 'success' (bool)
    if not data.get("success"):
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found", "message": data.get("message", "IP not found or lookup failed")},
        )

    return {
        "ip": data.get("ip"),
        "success": True,
        "type": data.get("type"),
        "continent": data.get("continent"),
        "country": data.get("country"),
        "region": data.get("region"),
        "city": data.get("city"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "is_eu": data.get("is_eu"),
        "asn": data.get("connection", {}).get("asn"),
        "org": data.get("connection", {}).get("org"),
        "isp": data.get("connection", {}).get("isp"),
        "timezone": data.get("timezone", {}).get("id"),
        "utc": data.get("timezone", {}).get("utc"),
    }
