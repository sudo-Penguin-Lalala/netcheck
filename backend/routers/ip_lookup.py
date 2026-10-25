"""GET /api/ip-lookup — detailed IP/GeoIP via ipwhois.io."""
import os
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from backend.utils.http_client import get_http_client
from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import is_private_ip, is_valid_ip, require_auth

router = APIRouter()
_TIMEOUT = 10.0

@router.get("/ip-lookup", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def ip_lookup(request: Request, ip: str = Query(..., min_length=7)):
    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail={"error": "bad_input", "message": "Invalid IP address: Must be a valid IPv4 or IPv6 format"})
    
    if is_private_ip(ip):
         raise HTTPException(status_code=400, detail={"error": "forbidden", "message": "RFC 1918 Forbidden: Geolocation and ASN lookups are not supported for private/loopback IPs"})

    api_key = os.environ.get("IPWHOIS_API_KEY", "").strip()
    
    # ipwhois.io uses different domains for free vs pro
    if api_key:
        url = f"https://ipwhois.pro/{ip}?key={api_key}"
    else:
        url = f"https://ipwho.is/{ip}"

    client = get_http_client()
    data = None
    try:
        resp = await client.get(url, timeout=_TIMEOUT)
        if resp.status_code == 200:
            res_data = resp.json()
            if res_data.get("success"):
                data = res_data
    except (httpx.HTTPError, ValueError):
        pass

    # Fallback to ip-api.com if primary failed and no custom pro api_key was provided
    if not data and not api_key:
        try:
            fb_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as,query"
            resp = await client.get(fb_url, timeout=_TIMEOUT)
            if resp.status_code == 200:
                fb_data = resp.json()
                if fb_data.get("status") == "success":
                    as_raw = fb_data.get("as") or ""
                    asn_val = None
                    if as_raw.startswith("AS"):
                        parts = as_raw.split(" ", 1)
                        try:
                            asn_val = int(parts[0][2:])
                        except ValueError:
                            pass
                    return {
                        "ip": fb_data.get("query") or ip,
                        "success": True,
                        "type": "IPv6" if ":" in ip else "IPv4",
                        "continent": "",
                        "country": fb_data.get("country"),
                        "region": fb_data.get("regionName"),
                        "city": fb_data.get("city"),
                        "latitude": fb_data.get("lat"),
                        "longitude": fb_data.get("lon"),
                        "is_eu": False,
                        "asn": asn_val,
                        "org": fb_data.get("org"),
                        "isp": fb_data.get("isp"),
                        "timezone": fb_data.get("timezone"),
                        "utc": "",
                    }
        except (httpx.HTTPError, ValueError):
            pass

    if not data or not data.get("success"):
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream_failure", "message": "All IP lookup upstreams failed to respond or returned invalid data"},
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
