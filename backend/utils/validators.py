"""Input validation: hostnames, IPs, and RFC1918 gating for subprocess routes."""
import asyncio
import ipaddress
import logging
import os
import re
import socket
import time

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
    """Check if IP address is private/loopback/reserved.

    SECURITY: Handles IPv6-mapped IPv4 addresses (::ffff:x.x.x.x) by
    extracting and checking the embedded IPv4 address.
    """
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False

    # Normalize IPv6-mapped IPv4 (::ffff:192.168.1.1 → 192.168.1.1)
    if hasattr(ip, 'ipv4_mapped') and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

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


async def _resolve_all_ips(host: str, timeout: float = 2.0) -> set[str]:
    """Resolve hostname to all IPs (IPv4 + IPv6) with timeout.

    Returns empty set on resolution failure.
    """
    def _sync_resolve():
        try:
            results = socket.getaddrinfo(
                host, None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                flags=socket.AI_ADDRCONFIG
            )
            return {sa[0] for fam, _, _, _, sa in results
                    if fam in (socket.AF_INET, socket.AF_INET6)}
        except (socket.gaierror, socket.timeout, OSError):
            return set()

    return await asyncio.to_thread(_sync_resolve)


async def is_private_target_blocked(host: str) -> bool:
    """Return True when the target is a private/loopback address and the deploy
    has not opted in via ALLOW_PRIVATE_TARGETS.

    SECURITY: Uses dual-resolution DNS rebinding mitigation - resolves twice
    with delay and requires consistency.
    """
    if _allow_private_targets():
        return False  # Trusted deploy → allow private

    if is_valid_ip(host):
        return is_private_ip(host)

    # Hostnames: Mitigate DNS rebinding with dual-resolution consistency check
    # Resolution 1: Initial check
    ips_first = await _resolve_all_ips(host, timeout=2.0)
    if not ips_first:
        # Resolution failed - block by default (fail-closed)
        log.warning(f"DNS resolution failed for {host}, blocking as fail-closed")
        return True

    # Check if ANY resolved IP is private
    has_private = any(is_private_ip(ip) for ip in ips_first)
    if has_private:
        return True  # Definitely private - block immediately

    # Resolution 2: Re-resolve after short delay to detect rebinding
    await asyncio.sleep(0.5)  # 500ms delay to catch fast DNS updates
    ips_second = await _resolve_all_ips(host, timeout=2.0)

    if not ips_second:
        # Second resolution failed - suspicious, block
        log.warning(f"DNS resolution inconsistent for {host}, blocking")
        return True

    # Consistency check: IPs must have at least one address in common (overlap)
    # CDNs like Google often return different subsets of IPs, so exact match (==) breaks.
    # A true DNS rebinding attack typically switches the entire record.
    if not (ips_first & ips_second):
        # DNS changed entirely between checks - likely rebinding attack
        log.warning(
            f"DNS rebinding detected for {host}: "
            f"no overlap between first={ips_first} and second={ips_second}. Blocking."
        )
        return True

    # Check second resolution for private IPs (defense in depth)
    has_private_second = any(is_private_ip(ip) for ip in ips_second)
    return has_private_second


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
