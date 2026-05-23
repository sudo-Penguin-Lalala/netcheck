"""Input validation: hostnames, IPs, and RFC1918 gating for subprocess routes."""
import ipaddress
import os
import re
import socket

from fastapi import HTTPException, Request

# RFC 1123 hostname: labels of 1-63 chars, total <= 253, no leading/trailing hyphen
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_valid_hostname(host: str) -> bool:
    if not host or host.endswith("."):
        return False
    return bool(_HOSTNAME_RE.match(host))


def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_valid_host_or_ip(s: str) -> bool:
    return is_valid_ip(s) or is_valid_hostname(s)


def is_private_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _auth_token() -> str:
    return os.environ.get("AUTH_TOKEN", "").strip()


def is_private_target_blocked(host: str) -> bool:
    """Return True when the target is a private/loopback address and the deploy
    has not declared itself trusted via AUTH_TOKEN."""
    if _auth_token():
        return False  # trusted deploy → allow private
    if is_valid_ip(host):
        return is_private_ip(host)
    # Hostnames may resolve to private addresses (router.local, *.lan)
    socket.setdefaulttimeout(3)
    try:
        for fam, _stype, _proto, _canon, sa in socket.getaddrinfo(host, None):
            if fam in (socket.AF_INET, socket.AF_INET6) and is_private_ip(sa[0]):
                return True
    except (socket.gaierror, OSError):
        return False
    finally:
        socket.setdefaulttimeout(None)
    return False


async def require_auth(request: Request) -> None:
    """If AUTH_TOKEN env is set, require Authorization: Bearer header to match."""
    token = _auth_token()
    if not token:
        return  # auth disabled — public deploy
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Missing or invalid Authorization header"},
        )
    if auth[len("Bearer ") :].strip() != token:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Invalid token"},
        )
