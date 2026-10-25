"""WHOIS lookup service: handles RDAP (RFC 7480), python-whois, and raw TCP socket fallback.

Some TLDs aren't in python-whois's hardcoded server table, so it either raises
or returns empty fields. Fall back to a manual two-step query:
  1. whois.iana.org port 43 → "refer: whois.X" line for the TLD
  2. that server port 43 → raw whois record for the full domain
"""
import asyncio
import json
import socket

import whois as whois_lib
from fastapi import HTTPException

from backend.utils.http_client import get_http_client
from backend.utils.validators import is_private_ip, is_valid_ip

WHOIS_TIMEOUT = 15.0  # seconds
SOCKET_TIMEOUT = 10.0
MAX_WHOIS_BYTES = 512 * 1024  # 512 KB hard cap per SSRF/DoS hardening
WHOIS_CACHE_TTL = 43200  # 12 hours
WHOIS_SEMAPHORE = asyncio.Semaphore(5)  # Cap concurrent blocking socket ops


def scalarize(value: any) -> str | None:
    """Pick the last (most authoritative) value instead of returning an array.

    When python-whois queries multiple servers (IANA → TLD registrar), the last
    response is usually the most specific and authoritative.
    """
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        return str(value[-1])
    return str(value)


def is_safe_whois_server(server: str) -> bool:
    """Refuse to connect to a referral that resolves to a private/loopback IP.

    The IANA `refer:` field is attacker-influenced when a malicious TLD or
    DNS-rebinding chain is in play. We resolve and validate every address
    before opening the TCP-43 socket.
    """
    server = (server or "").strip().rstrip(".")
    if not server:
        return False
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


def whois_socket(server: str, query: str) -> str:
    """Execute WHOIS query with DNS rebinding protection.

    SECURITY: Re-validates server IPs immediately before connection to prevent
    DNS rebinding attacks between validation and connection.
    """
    if not is_safe_whois_server(server):
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream_failure", "message": f"refusing WHOIS to non-public server: {server}"}
        )

    try:
        infos = socket.getaddrinfo(server, 43, type=socket.SOCK_STREAM)
        if not infos:
            raise HTTPException(
                status_code=502,
                detail={"error": "upstream_failure", "message": f"Cannot resolve WHOIS server: {server}"}
            )

        for fam, _stype, _proto, _canon, sa in infos:
            if fam not in (socket.AF_INET, socket.AF_INET6):
                continue
            if is_private_ip(sa[0]):
                raise HTTPException(
                    status_code=502,
                    detail={"error": "upstream_failure", "message": f"WHOIS server {server} resolved to private IP {sa[0]}"}
                )

        target_ip = infos[0][4][0]

        with socket.create_connection((target_ip, 43), timeout=SOCKET_TIMEOUT) as s:
            s.settimeout(SOCKET_TIMEOUT)
            s.sendall((query + "\r\n").encode("ascii", errors="ignore"))
            chunks: list[bytes] = []
            total = 0
            while True:
                data = s.recv(4096)
                if not data:
                    break
                total += len(data)
                if total > MAX_WHOIS_BYTES:
                    remaining = MAX_WHOIS_BYTES - (total - len(data))
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


def find_field(text: str, *keys: str) -> str | None:
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


def parse_nameservers(text: str) -> list[str]:
    keys = {"name server", "nserver", "nameserver", "name servers", "dns"}
    seen: list[str] = []
    seen_lower: set[str] = set()
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        if k.strip().lower() not in keys:
            continue
        val = v.strip().split()
        if not val:
            continue
        host = val[0].rstrip(".")
        if host.lower() not in seen_lower:
            seen.append(host)
            seen_lower.add(host.lower())
    return seen


async def iana_refer(tld: str) -> str | None:
    """Query IANA for TLD referral server. Wrapped in semaphore + timeout."""
    try:
        async with WHOIS_SEMAPHORE:
            text = await asyncio.wait_for(
                asyncio.to_thread(whois_socket, "whois.iana.org", tld),
                timeout=5.0
            )
    except (OSError, asyncio.TimeoutError, HTTPException):
        return None
    return find_field(text, "refer", "whois")


async def raw_fallback(domain: str) -> dict | None:
    """Two-hop WHOIS via IANA → TLD-specific server. None when no referral exists."""
    parts = domain.rsplit(".", 1)
    if len(parts) < 2 or not parts[-1]:
        return None
    tld = parts[-1].lower()
    server = await iana_refer(tld)
    if not server:
        return None
    try:
        async with WHOIS_SEMAPHORE:
            raw = await asyncio.wait_for(
                asyncio.to_thread(whois_socket, server, domain),
                timeout=5.0
            )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail={"error": "timeout", "message": f"WHOIS Timeout: Server '{server}:43' failed to respond within 5000ms"}
        )
    return {
        "raw": raw,
        "registrar": find_field(
            raw, "registrar", "sponsoring registrar", "registrar name", "organisation"
        ),
        "created": find_field(
            raw,
            "created",
            "creation date",
            "registered",
            "registered on",
            "domain registered",
            "created on",
        ),
        "expires": find_field(
            raw,
            "expires",
            "expiration date",
            "expiry date",
            "registry expiry date",
            "registrar registration expiration date",
            "expires on",
            "renewal date",
        ),
        "nameservers": parse_nameservers(raw),
    }


def is_record_empty(result: dict) -> bool:
    """True when python-whois returned a shell record with no useful fields."""
    return not (
        result.get("registrar")
        or result.get("created")
        or result.get("expires")
        or result.get("nameservers")
    )


async def query_rdap(target: str) -> dict | None:
    """Query ICANN/RIR RDAP REST API (RFC 7480-7484) via rdap.org bootstrap."""
    cli = get_http_client()
    try:
        url = f"https://rdap.org/domain/{target.lower().strip()}"
        resp = await cli.get(url, follow_redirects=True, timeout=6.0)
        if resp.status_code != 200:
            return None
        data = resp.json()

        registrar = None
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                vcard = ent.get("vcardArray")
                if vcard and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn" and len(item) > 3:
                            registrar = item[3]
                            break
                if not registrar:
                    registrar = ent.get("handle")
                break

        created = expires = None
        for ev in data.get("events", []):
            act = ev.get("eventAction")
            if act == "registration":
                created = ev.get("eventDate")
            elif act == "expiration":
                expires = ev.get("eventDate")

        ns = [n.get("ldhName") for n in data.get("nameservers", []) if n.get("ldhName")]
        if not (registrar or created or expires or ns):
            return None

        return {
            "raw": json.dumps(data, indent=2),
            "registrar": registrar,
            "created": created,
            "expires": expires,
            "nameservers": ns,
        }
    except Exception:
        return None


async def fetch_whois_data(target: str) -> dict:
    """Fetch WHOIS data via RDAP → python-whois → raw socket fallback chain."""
    # 1. Modern RDAP REST protocol (RFC 7480-7484)
    rdap_result = await query_rdap(target)
    if rdap_result and not is_record_empty(rdap_result):
        return rdap_result

    # 2. python-whois library query
    primary_result: dict | None = None
    try:
        data = await asyncio.wait_for(
            asyncio.to_thread(whois_lib.whois, target), timeout=WHOIS_TIMEOUT
        )
        nameservers = data.name_servers if data and data.name_servers else []
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        primary_result = {
            "raw": getattr(data, "text", None) or str(data),
            "registrar": scalarize(data.registrar),
            "created": scalarize(data.creation_date),
            "expires": scalarize(data.expiration_date),
            "nameservers": [str(n) for n in nameservers],
        }
    except Exception:
        # Fall through to raw socket fallback
        primary_result = None

    # 4. IANA → TLD server raw socket fallback
    if primary_result is None or is_record_empty(primary_result):
        fallback = await raw_fallback(target)
        if fallback and not is_record_empty(fallback):
            return fallback

        return {
            "raw": "This TLD does not publish a public WHOIS/RDAP server. No data available.",
            "registrar": None,
            "created": None,
            "expires": None,
            "nameservers": [],
        }

    return primary_result
