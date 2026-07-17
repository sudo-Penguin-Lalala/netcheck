"""Globalping API client — remote-probe network measurements.

Globalping (https://globalping.io) runs network tests from probes worldwide.
Probes do the work; our origin never touches the target. This prevents
origin-IP leakage that local subprocess traceroute/ping would otherwise
expose, even when the HTTP layer sits behind Cloudflare.

Free, no auth required (250 measurements/hour anon, higher with token).
"""
import asyncio
import os
from typing import Any

import httpx

API_BASE = os.environ.get("GLOBALPING_API", "https://api.globalping.io/v1").rstrip("/")
GP_TOKEN = os.environ.get("GLOBALPING_TOKEN", "").strip()

_POLL_INTERVAL = 1.0
_POLL_TIMEOUT = 35.0

# Continent magic-codes accepted by Globalping `locations: [{magic: ...}]`.
# https://globalping.io/docs — keep "world" as the default no-constraint value.
VALID_LOCATIONS = {"world", "NA", "EU", "AS", "SA", "AF", "OC"}


def normalize_location(loc: str | None) -> str:
    """Coerce a user-supplied location string to a valid magic code.
    Unknown / empty input falls back to "world"."""
    if not loc:
        return "world"
    raw = loc.strip()
    if raw in VALID_LOCATIONS:
        return raw
    upper = raw.upper()
    if upper in VALID_LOCATIONS:
        return upper
    return "world"


def build_locations(loc: str | None) -> list[dict[str, str]] | None:
    """Return the `locations` list to merge into a measurement payload.
    None when no constraint (Globalping picks the closest probe to target)."""
    code = normalize_location(loc)
    if code == "world":
        return None  # let Globalping pick — fastest path
    return [{"magic": code}]


class GlobalpingError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _headers() -> dict[str, str]:
    h = {"Accept": "application/json", "Content-Type": "application/json"}
    if GP_TOKEN:
        h["Authorization"] = f"Bearer {GP_TOKEN}"
    return h


async def _submit(client: httpx.AsyncClient, payload: dict[str, Any]) -> str:
    r = await client.post(f"{API_BASE}/measurements", json=payload, headers=_headers())
    if r.status_code == 202:
        return r.json()["id"]
    if r.status_code == 422:
        msg = "Invalid target or measurement options"
        try:
            detail = r.json()
            if isinstance(detail, dict):
                msg = detail.get("error", {}).get("message") or msg
        except Exception:
            pass
        raise GlobalpingError(400, "bad_input", msg)
    if r.status_code == 429:
        raise GlobalpingError(429, "upstream_rate_limited", "Globalping rate limit reached; try again later")
    if 500 <= r.status_code < 600:
        raise GlobalpingError(502, "upstream_failure", f"Globalping {r.status_code}")
    raise GlobalpingError(502, "upstream_failure", f"Unexpected status {r.status_code}")


async def _poll(client: httpx.AsyncClient, mid: str) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + _POLL_TIMEOUT
    while True:
        r = await client.get(f"{API_BASE}/measurements/{mid}", headers=_headers())
        if r.status_code != 200:
            raise GlobalpingError(502, "upstream_failure", f"Poll {r.status_code}")
        body = r.json()
        if body.get("status") == "finished":
            return body
        if asyncio.get_running_loop().time() >= deadline:
            raise GlobalpingError(504, "timeout", "Globalping measurement did not finish in time")
        await asyncio.sleep(_POLL_INTERVAL)


async def run_measurement(payload: dict[str, Any]) -> dict[str, Any]:
    """Submit + poll a Globalping measurement. Returns full response body."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        mid = await _submit(client, payload)
        return await _poll(client, mid)
