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

from backend.routers import api_router
from backend.utils.rate_limit import limiter
from backend.utils.validators import _auth_token

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


from fastapi.middleware.gzip import GZipMiddleware
from backend.utils.http_client import close_http_client, get_http_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Warm up shared connection pool for outbound lookups and Globalping
    get_http_client()
    yield
    # Gracefully close connection pool on shutdown
    await close_http_client()


app = FastAPI(
    title="NetCheck",
    description="Self-hosted network diagnostic toolkit",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter

# --- Response Compression: compress responses >= 1KB (reduces WHOIS/MTR transfer size by ~70%) ---
app.add_middleware(GZipMiddleware, minimum_size=1000)


# --- CORS: opt-in via ALLOWED_ORIGINS env var. Default = same-origin only. ---
_allowed_raw = os.environ.get("ALLOWED_ORIGINS", "").strip()
if _allowed_raw:
    if _allowed_raw == "*":
        # SECURITY WARNING: CORS wildcard allows any origin to make authenticated
        # requests. Only use in development. For production, set specific origins.
        import logging
        logging.getLogger(__name__).warning(
            "SECURITY: ALLOWED_ORIGINS=* permits any website to access this API. "
            "Set specific origins in production: ALLOWED_ORIGINS=https://app.example.com"
        )
        _origins: list[str] = ["*"]
    else:
        _origins = [o.strip() for o in _allowed_raw.split(",") if o.strip()]

    # Validate that origins are well-formed URLs
    import re
    _url_pattern = re.compile(r'^https?://[a-zA-Z0-9.-]+(:[0-9]+)?$')
    _validated_origins = []
    for origin in _origins:
        if origin == "*" or _url_pattern.match(origin):
            _validated_origins.append(origin)
        else:
            logging.getLogger(__name__).warning(
                f"Ignoring malformed CORS origin: {origin}"
            )

    if _validated_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=_validated_origins,
            # Browsers reject credentials when origin is "*"; honor that
            allow_credentials=_validated_origins != ["*"],
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
            max_age=600,
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
    return _error(429, "rate_limited", f"Rate Limit Exceeded (HTTP 429): Quota {exc.detail}. Back off before retrying.")


# --- Security response headers ---------------------------------------------
# Lock the page down so nothing third-party can run / load. Google Fonts is
# Completely self-contained: fonts and assets are served locally from origin.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self' https://ipv4.icanhazip.com https://ipv6.icanhazip.com https://api4.ipify.org https://api6.ipify.org; "
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
    # Cache optimization: API responses must not be cached by proxies/browsers,
    # while static assets (css, js, svg) are cached with revalidation.
    path = request.url.path
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    elif path.endswith((".css", ".js", ".svg", ".png", ".woff2", ".ttf")):
        response.headers["Cache-Control"] = "public, max-age=86400, stale-while-revalidate=3600"
    elif path in ("/", "/index.html"):
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    return response


# --- API routes ------------------------------------------------------------
app.include_router(api_router)


@app.get("/api/healthz", tags=["meta"])
async def healthz():
    return {
        "status": "ok",
        "auth_required": bool(_auth_token()),
    }


# --- Static frontend (last so /api/* wins) ---------------------------------
if _FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=_FRONTEND_DIR, html=True), name="frontend")
