"""GET /api/headers — echo the client's request headers (filtered)."""
from fastapi import APIRouter, Depends, Request

from backend.utils.validators import require_auth

router = APIRouter()

# Noise headers that describe the transport, not the client.
_DROP = frozenset({"host", "connection", "content-length"})


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
