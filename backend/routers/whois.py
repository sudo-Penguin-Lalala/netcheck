"""POST /api/whois — domain WHOIS lookup endpoint."""
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.services.whois_service import WHOIS_CACHE_TTL, fetch_whois_data
from backend.utils.cache import cache_key, get_or_fetch
from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import is_valid_hostname, require_auth

router = APIRouter()


class WhoisRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)


@router.post("/whois", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def whois_lookup(request: Request, body: WhoisRequest):
    target = body.target.strip().lower().rstrip(".")

    if not is_valid_hostname(target):
        raise HTTPException(
            400,
            {"error": "bad_input", "message": "Invalid domain: Must be a valid FQDN (e.g. domain.com)"}
        )

    # Stampede-safe cached fetch via diskcache
    key = cache_key("whois", target=target)
    try:
        return await get_or_fetch(key, WHOIS_CACHE_TTL, lambda: fetch_whois_data(target))
    except asyncio.TimeoutError:
        raise HTTPException(
            504,
            {"error": "upstream_timeout", "message": "WHOIS Timeout: Upstream registry server did not respond within 15000ms"}
        )
