"""POST /api/rdns — reverse DNS via dnspython."""
import asyncio
import dns.exception
import dns.resolver
import dns.reversename

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import is_valid_ip, require_auth

router = APIRouter()
_RDNS_TIMEOUT = 5.0

_resolver = dns.resolver.Resolver()
_resolver.lifetime = _RDNS_TIMEOUT
_resolver.timeout = _RDNS_TIMEOUT


class RdnsRequest(BaseModel):
    ip: str = Field(min_length=1, max_length=45)


@router.post("/rdns", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def reverse_dns(request: Request, body: RdnsRequest):
    ip = body.ip.strip()

    if not is_valid_ip(ip):
        raise HTTPException(400, {"error": "bad_input", "message": "Invalid IP address"})

    try:
        rev_name = dns.reversename.from_address(ip)
        answer = await asyncio.to_thread(_resolver.resolve, rev_name, "PTR")
        hostname = str(answer[0]).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        raise HTTPException(
            400, {"error": "no_ptr", "message": f"No PTR record for {ip}"}
        )
    except dns.exception.Timeout:
        raise HTTPException(
            504, {"error": "timeout", "message": "Reverse DNS lookup timed out"}
        )
    except Exception as e:
        raise HTTPException(
            500, {"error": "lookup_error", "message": f"Reverse DNS lookup failed: {e}"}
        )

    return {"ip": ip, "hostname": hostname}
