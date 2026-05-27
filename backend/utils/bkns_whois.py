"""BKNS Whois API client for .vn domains.

BKNS (https://whois.bkns.vn) provides direct VNNIC relay for Vietnamese domains
with ~145ms latency. Supports 1,260+ TLDs but optimized for .vn variants.

Free tier: 10 req/min (no API key)
Partner tier: 300 req/min (requires BKNS_API_KEY env var)
"""
import os
from typing import Any

import httpx

API_BASE = "https://whois.bkns.vn/api/v1"
BKNS_API_KEY = os.environ.get("BKNS_API_KEY", "").strip()
def is_vn_domain(domain: str) -> bool:
    """Check if domain is .vn or any .vn variant (all sectors, provinces, IDN)."""
    return domain.lower().endswith(".vn")


async def query_bkns(domain: str) -> dict[str, Any] | None:
    """Query BKNS API for domain WHOIS data.

    Returns NetCheck-format dict on success, None on any error (triggers fallback).

    NetCheck format:
    {
        "raw": str,           # Human-readable WHOIS text
        "registrar": str | None,
        "created": str | None,    # ISO 8601
        "expires": str | None,    # ISO 8601
        "nameservers": list[str]
    }
    """
    headers = {"Accept": "application/json"}
    if BKNS_API_KEY:
        headers["X-API-Key"] = BKNS_API_KEY

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                f"{API_BASE}/whois",
                params={"domain": domain},
                headers=headers,
            )

            # Rate limited (429) → fall back to python-whois
            if r.status_code == 429:
                return None

            # Auth/validation errors (400, 401) → fall back
            if r.status_code in (400, 401):
                return None

            # Server errors (5xx) → fall back
            if r.status_code >= 500:
                return None

            # Unexpected status → fall back
            if r.status_code != 200:
                return None

            data = r.json()

            # Domain not registered
            if data.get("status") != "registered":
                return {
                    "raw": f"Domain {domain} is not registered (BKNS API)",
                    "registrar": None,
                    "created": None,
                    "expires": None,
                    "nameservers": [],
                }

            # Transform BKNS response to NetCheck format
            bkns_data = data.get("data", {})
            registrant = bkns_data.get("registrant", {}).get("name")
            registrar = bkns_data.get("registrar", {}).get("name")
            dates = bkns_data.get("dates", {})
            nameservers = bkns_data.get("nameservers", [])
            domain_status = bkns_data.get("domainStatus", [])
            dnssec = bkns_data.get("dnssec", False)

            # Format raw output (human-readable)
            raw_lines = [
                f"Domain: {domain}",
                f"Status: {data.get('status')}",
                f"Source: BKNS API (VNNIC relay)",
                "",
            ]
            if registrant:
                raw_lines.append(f"Registrant: {registrant}")
            if registrar:
                raw_lines.append(f"Registrar: {registrar}")
            if dates.get("created"):
                raw_lines.append(f"Created: {dates['created']}")
            if dates.get("updated"):
                raw_lines.append(f"Updated: {dates['updated']}")
            if dates.get("expiry"):
                raw_lines.append(f"Expires: {dates['expiry']}")
            if nameservers:
                raw_lines.append("")
                raw_lines.append("Nameservers:")
                for ns in nameservers:
                    raw_lines.append(f"  {ns}")
            if domain_status:
                raw_lines.append("")
                raw_lines.append(f"Domain Status: {', '.join(domain_status)}")
            if dnssec:
                raw_lines.append("DNSSEC: enabled")

            return {
                "raw": "\n".join(raw_lines),
                "registrar": registrar,
                "created": dates.get("created"),
                "expires": dates.get("expiry"),
                "nameservers": nameservers,
            }

    except Exception:
        # Any error (network, timeout, parse) → fall back to python-whois
        return None
