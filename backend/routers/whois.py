"""POST /api/whois — domain WHOIS with python-whois + raw socket fallback.

Some TLDs (notably .vn, .io.vn, .id, several ccTLDs) aren't in python-whois's
hardcoded server table, so it either raises or returns empty fields. Fall
back to a manual two-step query:

  1. whois.iana.org port 43 → "refer: whois.X" line for the TLD
  2. that server port 43 → raw whois record for the full domain

We then parse the common fields (registrar / creation / expiry / name
servers) out of the raw text using line-prefix matching that handles the
half-dozen common label variants seen in real ccTLD output.

Persistent disk cache (12h default) via diskcache, replaces old in-memory dict.
"""
import asyncio
import socket

import whois as whois_lib
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.utils.cache import cache_key, get_or_fetch
from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import (
    is_private_ip,
    is_valid_hostname,
    is_valid_ip,
    require_auth,
)
from backend.utils.bkns_whois import is_vn_domain, query_bkns

router = APIRouter()
_WHOIS_TIMEOUT = 15  # seconds
_SOCKET_TIMEOUT = 10.0
_MAX_WHOIS_BYTES = 512 * 1024  # 512 KB hard cap per SSRF/DoS hardening
_CACHE_TTL = 43200  # 12 hours
_WHOIS_SEMAPHORE = asyncio.Semaphore(5)  # Cap concurrent blocking socket ops


def _scalarize(value: any) -> str | None:
    """python-whois returns lists when multiple WHOIS servers reply.

    Pick the last (most authoritative) value instead of returning the whole array.
    When python-whois queries multiple servers (IANA → TLD registrar), the last
    response is usually the most specific and authoritative.
    """
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        # Take the last value - python-whois queries in order of increasing specificity
        return str(value[-1])
    return str(value)


def _is_safe_whois_server(server: str) -> bool:
    """Refuse to connect to a referral that resolves to a private/loopback IP.

    The IANA `refer:` field is attacker-influenced when a malicious TLD or
    DNS-rebinding chain is in play. We resolve and validate every address
    before opening the TCP-43 socket.
    """
    server = (server or "").strip().rstrip(".")
    if not server:
        return False
    # If the referral is already a literal IP, just check it directly.
    if is_valid_ip(server):
        return not is_private_ip(server)
    try:
        infos = socket.getaddrinfo(server, 43, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return False
    if not infos:
        return False
    for fam, _stype, _proto, _canon, sa in infos:
        if fam not in (socket.AF_INET, socket.AF_INET6):
            continue
        if is_private_ip(sa[0]):
            return False
    return True


def _whois_socket(server: str, query: str) -> str:
    """Execute WHOIS query with DNS rebinding protection.

    SECURITY: Re-validates server IPs immediately before connection to prevent
    DNS rebinding attacks between validation and connection.
    """
    if not _is_safe_whois_server(server):
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream_failure", "message": f"refusing WHOIS to non-public server: {server}"}
        )

    try:
        # Resolve to specific IP addresses (don't let create_connection resolve again)
        infos = socket.getaddrinfo(server, 43, type=socket.SOCK_STREAM)
        if not infos:
            raise HTTPException(
                status_code=502,
                detail={"error": "upstream_failure", "message": f"Cannot resolve WHOIS server: {server}"}
            )

        # Re-validate EVERY resolved IP immediately before connection
        for fam, _stype, _proto, _canon, sa in infos:
            if fam not in (socket.AF_INET, socket.AF_INET6):
                continue
            if is_private_ip(sa[0]):
                raise HTTPException(
                    status_code=502,
                    detail={"error": "upstream_failure", "message": f"WHOIS server {server} resolved to private IP {sa[0]}"}
                )

        # Connect to FIRST valid IP (already validated above)
        target_ip = infos[0][4][0]

        with socket.create_connection((target_ip, 43), timeout=_SOCKET_TIMEOUT) as s:
            s.settimeout(_SOCKET_TIMEOUT)
            s.sendall((query + "\r\n").encode("ascii", errors="ignore"))
            chunks: list[bytes] = []
            total = 0
            while True:
                data = s.recv(4096)
                if not data:
                    break
                total += len(data)
                if total > _MAX_WHOIS_BYTES:
                    remaining = _MAX_WHOIS_BYTES - (total - len(data))
                    if remaining > 0:
                        chunks.append(data[:remaining])
                    break
                chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except socket.timeout:
        raise HTTPException(
            status_code=504,
            detail={"error": "timeout", "message": f"WHOIS query to {server} timed out"}
        )
    except OSError as e:
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream_failure", "message": f"WHOIS connection failed: {e}"}
        )


def _field(text: str, *keys: str) -> str | None:
    """First matching `key: value` line (case-insensitive). Returns None if absent."""
    wanted = {k.lower() for k in keys}
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        if k.strip().lower() in wanted:
            val = v.strip()
            if val:
                return val
    return None


def _parse_nameservers(text: str) -> list[str]:
    keys = {"name server", "nserver", "nameserver", "name servers", "dns"}
    seen: list[str] = []
    seen_lower: set[str] = set()
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        if k.strip().lower() not in keys:
            continue
        val = v.strip().split()  # some servers append IPs
        if not val:
            continue
        host = val[0].rstrip(".")
        if host.lower() not in seen_lower:
            seen.append(host)
            seen_lower.add(host.lower())
    return seen


async def _iana_refer(tld: str) -> str | None:
    """Query IANA for TLD referral server. Wrapped in semaphore + timeout."""
    try:
        async with _WHOIS_SEMAPHORE:
            text = await asyncio.wait_for(
                asyncio.to_thread(_whois_socket, "whois.iana.org", tld),
                timeout=5.0
            )
    except (OSError, asyncio.TimeoutError, HTTPException):
        return None
    return _field(text, "refer", "whois")


async def _raw_fallback(domain: str) -> dict | None:
    """Two-hop WHOIS via IANA → TLD-specific server. None when no referral exists."""
    parts = domain.rsplit(".", 1)
    if len(parts) < 2 or not parts[-1]:
        return None
    tld = parts[-1].lower()
    server = await _iana_refer(tld)
    if not server:
        return None
    try:
        async with _WHOIS_SEMAPHORE:
            raw = await asyncio.wait_for(
                asyncio.to_thread(_whois_socket, server, domain),
                timeout=5.0
            )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail={"error": "timeout", "message": f"WHOIS query to {server} timed out after 5 seconds"})
    return {
        "raw": raw,
        "registrar": _field(
            raw, "registrar", "sponsoring registrar", "registrar name", "organisation"
        ),
        "created": _field(
            raw,
            "created",
            "creation date",
            "registered",
            "registered on",
            "domain registered",
            "created on",
        ),
        "expires": _field(
            raw,
            "expires",
            "expiration date",
            "expiry date",
            "registry expiry date",
            "registrar registration expiration date",
            "expires on",
            "renewal date",
        ),
        "nameservers": _parse_nameservers(raw),
    }


def _is_empty(result: dict) -> bool:
    """True when python-whois returned a shell record with no useful fields."""
    return not (
        result.get("registrar")
        or result.get("created")
        or result.get("expires")
        or result.get("nameservers")
    )


async def _fetch_whois_data(target: str) -> dict:
    """Fetch WHOIS data via BKNS → python-whois → raw socket fallback chain."""
    # --- Attempt 1: BKNS API for .vn domains ----------------------------
    if is_vn_domain(target):
        bkns_result = await query_bkns(target)
        if bkns_result:
            return bkns_result
        # Fall through to python-whois if BKNS fails

    # --- Attempt 2: python-whois -------------------------------------------
    primary_result: dict | None = None
    primary_error: Exception | None = None
    try:
        data = await asyncio.wait_for(
            asyncio.to_thread(whois_lib.whois, target), timeout=_WHOIS_TIMEOUT
        )
        nameservers = data.name_servers if data and data.name_servers else []
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        primary_result = {
            "raw": getattr(data, "text", None) or str(data),
            "registrar": _scalarize(data.registrar),
            "created": _scalarize(data.creation_date),
            "expires": _scalarize(data.expiration_date),
            "nameservers": [str(n) for n in nameservers],
        }
    except asyncio.TimeoutError:
        primary_error = TimeoutError("python-whois timed out")
    except Exception as exc:  # python-whois throws broad exceptions on TLDs it doesn't know
        primary_error = exc

    # --- Attempt 3: IANA → TLD server raw socket fallback ------------------
    if primary_result is None or _is_empty(primary_result):
        fallback = await _raw_fallback(target)
        if fallback and not _is_empty(fallback):
            return fallback

        # Both attempts came back empty. Some ccTLD registries (notably .vn /
        # VNNIC) intentionally leave IANA's refer field blank, so two-hop
        # WHOIS can never work for them. Show a friendly message instead of
        # the raw socket / library error so the UI stays readable.
        return {
            "raw": "This TLD does not publish a public WHOIS server. No data available.",
            "registrar": None,
            "created": None,
            "expires": None,
            "nameservers": [],
        }

    return primary_result


class WhoisRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)


@router.post("/whois", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def whois_lookup(request: Request, body: WhoisRequest):
    target = body.target.strip().lower().rstrip(".")

    if not is_valid_hostname(target):
        raise HTTPException(400, {"error": "bad_input", "message": "Invalid domain"})

    # Stampede-safe cached fetch via diskcache
    key = cache_key("whois", target=target)
    try:
        result = await get_or_fetch(key, _CACHE_TTL, lambda: _fetch_whois_data(target))
        return result
    except asyncio.TimeoutError:
        raise HTTPException(504, {"error": "upstream_timeout", "message": "WHOIS query timed out"})
