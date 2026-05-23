"""POST /api/rdns — reverse DNS via socket.gethostbyaddr()."""
import socket

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import is_valid_ip, require_auth

router = APIRouter()


class RdnsRequest(BaseModel):
    ip: str = Field(min_length=1, max_length=45)


@router.post("/rdns", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def reverse_dns(request: Request, body: RdnsRequest):
    ip = body.ip.strip()

    if not is_valid_ip(ip):
        raise HTTPException(400, {"error": "bad_input", "message": "Invalid IP address"})

    socket.setdefaulttimeout(5)
    try:
        hostname, _aliases, _ips = socket.gethostbyaddr(ip)
    except socket.herror:
        raise HTTPException(
            400, {"error": "no_ptr", "message": f"No PTR record for {ip}"}
        )
    except socket.gaierror:
        raise HTTPException(
            500, {"error": "lookup_error", "message": "Reverse DNS lookup failed"}
        )
    finally:
        socket.setdefaulttimeout(None)

    return {"ip": ip, "hostname": hostname}
