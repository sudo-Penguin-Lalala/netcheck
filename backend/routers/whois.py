"""POST /api/whois — domain WHOIS with python-whois + raw socket fallback.

Some TLDs (notably .vn, .io.vn, .id, several ccTLDs) aren't in python-whois's
hardcoded server table, so it either raises or returns empty fields. Fall
back to a manual two-step query:

  1. whois.iana.org port 43 → "refer: whois.X" line for the TLD
  2. that server port 43 → raw whois record for the full domain

We then parse the common fields (registrar / creation / expiry / name
servers) out of the raw text using line-prefix matching that handles the
half-dozen common label variants seen in real ccTLD output.

1h in-memory cache by domain.
"""
import asyncio
import socket
import time

import whois as whois_lib
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from backend.utils.rate_limit import RATE_LIMIT, limiter
from backend.utils.validators import is_valid_hostname, require_auth

router = APIRouter()
_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 3600  # seconds
_WHOIS_TIMEOUT = 15  # seconds
_SOCKET_TIMEOUT = 10.0


def _scalarize(value):
    """python-whois returns lists when multiple WHOIS servers reply."""
    if value is None:
        return None
    if isinstance(value, list):
        return [str(v) for v in value]
    return str(value)


def _whois_socket(server: str, query: str) -> str:
    with socket.create_connection((server, 43), timeout=_SOCKET_TIMEOUT) as s:
        s.sendall((query + "\r\n").encode("ascii", errors="ignore"))
        chunks: list[bytes] = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


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


def _iana_refer(tld: str) -> str | None:
    try:
        text = _whois_socket("whois.iana.org", tld)
    except OSError:
        return None
    return _field(text, "refer", "whois")


def _raw_fallback(domain: str) -> dict | None:
    """Two-hop WHOIS via IANA → TLD-specific server. None when no referral exists."""
    parts = domain.rsplit(".", 1)
    if len(parts) < 2 or not parts[-1]:
        return None
    tld = parts[-1].lower()
    server = _iana_refer(tld)
    if not server:
        return None
    try:
        raw = _whois_socket(server, domain)
    except OSError as e:
        return {
            "raw": f"WHOIS query to {server} failed: {e}",
            "registrar": None,
            "created": None,
            "expires": None,
            "nameservers": [],
        }
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


class WhoisRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)


@router.post("/whois", dependencies=[Depends(require_auth)])
@limiter.limit(RATE_LIMIT)
async def whois_lookup(request: Request, body: WhoisRequest):
    target = body.target.strip().lower().rstrip(".")

    if not is_valid_hostname(target):
        raise HTTPException(400, {"error": "bad_input", "message": "Invalid domain"})

    now = time.time()
    cached = _CACHE.get(target)
    if cached and (now - cached[0]) < _CACHE_TTL:
        return cached[1]

    # --- Attempt 1: python-whois -------------------------------------------
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

    # --- Attempt 2: IANA → TLD server raw socket fallback ------------------
    if primary_result is None or _is_empty(primary_result):
        fallback = await asyncio.to_thread(_raw_fallback, target)
        if fallback and not _is_empty(fallback):
            _CACHE[target] = (now, fallback)
            return fallback

        # Both attempts came back empty. Some ccTLD registries (notably .vn /
        # VNNIC) intentionally leave IANA's refer field blank, so two-hop
        # WHOIS can never work for them. Show a friendly message instead of
        # the raw socket / library error so the UI stays readable.
        friendly = {
            "raw": "This TLD does not publish a public WHOIS server. No data available.",
            "registrar": None,
            "created": None,
            "expires": None,
            "nameservers": [],
        }
        _CACHE[target] = (now, friendly)
        return friendly

    _CACHE[target] = (now, primary_result)
    return primary_result
