"""POST /api/dns — DNS records via dnspython."""
import asyncio
import dns.exception
import dns.resolver
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import is_private_target_blocked, is_valid_hostname, require_auth

router = APIRouter()
_ALLOWED_TYPES = {"A", "AAAA", "MX", "TXT", "CNAME", "NS"}
_DNS_TIMEOUT = 5.0


class DnsRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    type: str = Field(default="A")


def _format_record(rec, rtype: str) -> str:
    s = str(rec)
    # dnspython quotes TXT records; strip the outer quotes for readability
    if rtype == "TXT" and len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


@router.post("/dns", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def dns_lookup(request: Request, body: DnsRequest):
    host = body.host.strip().lower().rstrip(".")
    rtype = body.type.strip().upper()

    if not is_valid_hostname(host):
        raise HTTPException(400, {"error": "bad_input", "message": "Invalid hostname"})
    if await is_private_target_blocked(host):
        raise HTTPException(
            403,
            {
                "error": "private_blocked",
                "message": "Private/loopback targets cannot be queried.",
            },
        )
    if rtype not in _ALLOWED_TYPES:
        raise HTTPException(
            400,
            {"error": "bad_input", "message": f"DNS type must be one of: {sorted(_ALLOWED_TYPES)}"},
        )

    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT
    resolver.timeout = _DNS_TIMEOUT

    try:
        answer = await asyncio.to_thread(resolver.resolve, host, rtype)
    except dns.resolver.NXDOMAIN:
        raise HTTPException(400, {"error": "nxdomain", "message": f"{host} does not exist"})
    except dns.resolver.NoAnswer:
        raise HTTPException(400, {"error": "no_answer", "message": f"No {rtype} records for {host}"})
    except dns.exception.Timeout:
        raise HTTPException(504, {"error": "timeout", "message": "DNS resolver timed out"})
    except dns.exception.DNSException as e:
        raise HTTPException(500, {"error": "dns_error", "message": str(e)})

    records = [_format_record(r, rtype) for r in answer]
    ttl = answer.rrset.ttl if answer.rrset is not None else 0
    resolver_addr = resolver.nameservers[0] if resolver.nameservers else "system"

    return {"records": records, "ttl": ttl, "resolver": resolver_addr}
