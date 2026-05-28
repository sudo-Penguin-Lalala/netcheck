"""GET /api/headers — echo the client's request headers (filtered)."""
from fastapi import APIRouter, Depends, Request

from backend.utils.validators import require_auth

router = APIRouter()

# Noise headers that describe the transport, not the client.
# `authorization` / `cookie` / `proxy-authorization` are dropped so an echo
# endpoint never reflects a bearer token, session cookie, or proxy credential
# back to a logger/screen-recorder/diagnostic dump.
_DROP = frozenset({"host", "connection", "content-length", "authorization", "cookie", "proxy-authorization"})


@router.get("/headers", dependencies=[Depends(require_auth)])
async def get_headers(request: Request):
    headers: dict[str, str] = {}
    for name, value in request.headers.items():
        key = name.lower()
        if key in _DROP:
            continue
        # Starlette can fold duplicate headers into a comma-separated value;
        # we surface whatever the framework hands us (already deduped on key).
        headers[key] = value
    return {"headers": headers}
