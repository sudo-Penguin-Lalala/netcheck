"""API router aggregation for NetCheck."""
from fastapi import APIRouter

from backend.routers import dns
from backend.routers import headers
from backend.routers import http_check
from backend.routers import ip
from backend.routers import ip_lookup
from backend.routers import mtr
from backend.routers import ping
from backend.routers import port
from backend.routers import rdns
from backend.routers import ssl_check
from backend.routers import traceroute
from backend.routers import whois

api_router = APIRouter(prefix="/api", tags=["api"])

for r in (
    ip.router,
    ip_lookup.router,
    dns.router,
    ping.router,
    traceroute.router,
    mtr.router,
    port.router,
    rdns.router,
    whois.router,
    headers.router,
    ssl_check.router,
    http_check.router,
):
    api_router.include_router(r)

__all__ = ["api_router"]
