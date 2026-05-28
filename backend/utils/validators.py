"""Input validation: hostnames, IPs, and RFC1918 gating for subprocess routes."""
import ipaddress
import logging
import os
import re
import socket

from fastapi import HTTPException, Request

log = logging.getLogger(__name__)
_warned_legacy_auth_allow = False

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


def _env_bool(name: str) -> bool | None:
    """Tri-state env parse: None=unset, True=truthy, False=falsy."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    v = raw.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off", ""):
        return False
    return None


def _allow_private_targets() -> bool:
    """Decoupled from AUTH_TOKEN: SSRF gating is its own setting.

    - ALLOW_PRIVATE_TARGETS=1 → allow private/loopback targets
    - ALLOW_PRIVATE_TARGETS=0 → block (default for new deploys)
    - ALLOW_PRIVATE_TARGETS unset + AUTH_TOKEN set → legacy behavior (allow + warn once)
    - ALLOW_PRIVATE_TARGETS unset + AUTH_TOKEN unset → block
    """
    global _warned_legacy_auth_allow
    explicit = _env_bool("ALLOW_PRIVATE_TARGETS")
    if explicit is not None:
        return explicit
    # Backwards-compat: AUTH_TOKEN used to imply private-target allow.
    if _auth_token():
        if not _warned_legacy_auth_allow:
            log.warning(
                "DEPRECATED: AUTH_TOKEN is enabling private-target access. "
                "Set ALLOW_PRIVATE_TARGETS=1 explicitly to silence this warning, "
                "or ALLOW_PRIVATE_TARGETS=0 to block private targets even with AUTH_TOKEN set. "
                "Legacy coupling will be removed in v2.0."
            )
            _warned_legacy_auth_allow = True
        return True
    return False


def is_private_target_blocked(host: str) -> bool:
    """Return True when the target is a private/loopback address and the deploy
    has not opted in via ALLOW_PRIVATE_TARGETS (or legacy AUTH_TOKEN)."""
    if _allow_private_targets():
        return False  # trusted deploy → allow private
    if is_valid_ip(host):
        return is_private_ip(host)
    # Hostnames may resolve to private addresses (router.local, *.lan)
    try:
        for fam, _stype, _proto, _canon, sa in socket.getaddrinfo(
            host, None, type=socket.SOCK_STREAM
        ):
            if fam in (socket.AF_INET, socket.AF_INET6) and is_private_ip(sa[0]):
                return True
    except (socket.gaierror, OSError):
        return False
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
