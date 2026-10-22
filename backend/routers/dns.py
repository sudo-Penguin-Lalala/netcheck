"""POST /api/dns — DNS records via dnspython."""
import asyncio
import logging
import dns.exception
import dns.resolver
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import is_valid_hostname, require_auth

log = logging.getLogger(__name__)
router = APIRouter()
_ALLOWED_TYPES = {"A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "CAA", "SRV", "PTR"}
_DNS_TIMEOUT = 5.0

_resolver = dns.resolver.Resolver()
_resolver.lifetime = _DNS_TIMEOUT
_resolver.timeout = _DNS_TIMEOUT


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
        raise HTTPException(400, {"error": "bad_input", "message": "Invalid hostname: Must be a valid FQDN (RFC 1123, max 253 chars)"})
    if rtype not in _ALLOWED_TYPES:
        raise HTTPException(
            400,
            {"error": "bad_input", "message": f"DNS type must be one of: {sorted(_ALLOWED_TYPES)}"},
        )

    try:
        answer = await asyncio.to_thread(_resolver.resolve, host, rtype)
    except dns.resolver.NXDOMAIN:
        raise HTTPException(400, {"error": "nxdomain", "message": f"NXDOMAIN: Domain '{host}' does not exist on authoritative nameservers"})
    except dns.resolver.NoAnswer:
        raise HTTPException(400, {"error": "no_answer", "message": f"NODATA: Query succeeded (NOERROR) but no {rtype} record exists for '{host}'"})
    except dns.exception.Timeout:
        raise HTTPException(504, {"error": "timeout", "message": "DNS Timeout: Upstream resolver did not respond within 5000ms"})
    except dns.exception.DNSException as e:
        log.warning("DNS resolution failed for %s (%s): %s", host, rtype, e)
        raise HTTPException(500, {"error": "dns_error", "message": "DNS resolution failed: Upstream returned SERVFAIL/REFUSED or network unreachable"})

    records = [_format_record(r, rtype) for r in answer]
    ttl = answer.rrset.ttl if answer.rrset is not None else 0
    resolver_addr = _resolver.nameservers[0] if _resolver.nameservers else "system"

    return {"records": records, "ttl": ttl, "resolver": resolver_addr}
