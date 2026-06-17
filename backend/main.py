# Copyright (c) 2026 NNT
# This file is part of NetCheck.
#
# NetCheck is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# NetCheck is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with NetCheck. If not, see <https://www.gnu.org/licenses/>.

"""NetCheck — FastAPI app entry. Mounts static frontend and JSON API."""
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.routers import dns as dns_router
from backend.routers import headers as headers_router
from backend.routers import http_check as http_router
from backend.routers import ip as ip_router
from backend.routers import mtr as mtr_router
from backend.routers import ping as ping_router
from backend.routers import port as port_router
from backend.routers import rdns as rdns_router
from backend.routers import ssl_check as ssl_router
from backend.routers import traceroute as trace_router
from backend.routers import whois as whois_router
from backend.utils.rate_limit import limiter

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_FRONTEND_DIR = _PROJECT_ROOT / "frontend"

_STATUS_TO_CODE = {
    400: "bad_input",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    502: "upstream_failure",
    504: "timeout",
}


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": code, "message": message})


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup hook (currently no-op; placeholder for future warmup tasks)
    yield
    # Shutdown hook


app = FastAPI(
    title="NetCheck",
    description="Self-hosted network diagnostic toolkit",
    version="1.0.0",
    # Docs surface fully disabled — API is only consumed by the bundled
    # frontend; no public OpenAPI / Swagger / ReDoc.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter


# --- CORS: opt-in via ALLOWED_ORIGINS env var. Default = same-origin only. ---
_allowed_raw = os.environ.get("ALLOWED_ORIGINS", "").strip()
if _allowed_raw:
    if _allowed_raw == "*":
        _origins: list[str] = ["*"]
    else:
        _origins = [o.strip() for o in _allowed_raw.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        # Browsers reject credentials when origin is "*"; honor that
        allow_credentials=_origins != ["*"],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )


# --- Unified error envelope -------------------------------------------------
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    detail = exc.detail
    if isinstance(detail, dict) and "error" in detail and "message" in detail:
        return JSONResponse(status_code=exc.status_code, content=detail)
    code = _STATUS_TO_CODE.get(exc.status_code, "error")
    return _error(exc.status_code, code, str(detail))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    msg = "Invalid input"
    if errors:
        first = errors[0]
        loc = ".".join(str(p) for p in first.get("loc", []) if p != "body")
        msg = f"{loc}: {first.get('msg', 'invalid')}" if loc else first.get("msg", msg)
    return _error(400, "validation_error", msg)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_exception_handler(request: Request, exc: RateLimitExceeded):
    return _error(429, "rate_limited", f"Rate limit exceeded ({exc.detail})")


# --- Security response headers ---------------------------------------------
# Lock the page down so nothing third-party can run / load. Google Fonts is
# the one remote dependency we keep (stylesheet + font files); everything
# else stays on the origin.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = _CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
    )
    return response


# --- API routers ------------------------------------------------------------
for router in (
    ip_router.router,
    dns_router.router,
    ping_router.router,
    trace_router.router,
    mtr_router.router,
    port_router.router,
    rdns_router.router,
    whois_router.router,
    headers_router.router,
    ssl_router.router,
    http_router.router,
):
    app.include_router(router, prefix="/api", tags=["api"])


@app.get("/api/healthz", tags=["meta"])
async def healthz():
    return {"status": "ok"}


# --- Static frontend (last so /api/* wins) ---------------------------------
if _FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=_FRONTEND_DIR, html=True), name="frontend")
