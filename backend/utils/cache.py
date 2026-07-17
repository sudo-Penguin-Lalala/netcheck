import os
import hashlib
import asyncio
import diskcache
from typing import Callable, Any, Awaitable

CACHE_DIR = os.environ.get("CACHE_DIR", "/data/netcheck-cache")
cache = diskcache.Cache(CACHE_DIR, disk=diskcache.JSONDisk)

_locks = {}
_locks_lock = asyncio.Lock()

def cache_key(namespace: str, **kwargs) -> str:
    """Generate a consistent cache key from namespace and kwargs."""
    parts = [namespace]
    for k in sorted(kwargs.keys()):
        parts.append(f"{k}={kwargs[k]}")
    raw_key = ":".join(parts)
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

async def get_or_fetch(key: str, ttl: int, fetch_func: Callable[[], Awaitable[Any]]) -> Any:
    """Get from cache, or fetch and store if missing, with stampede protection."""
    # Fast path without lock
    val = cache.get(key)
    if val is not None:
        return val

    # Acquire global lock to safely initialize per-key lock
    async with _locks_lock:
        if key not in _locks:
            _locks[key] = asyncio.Lock()
        lock = _locks[key]

    # Acquire per-key lock to prevent stampede for this specific key
    async with lock:
        # Check again in case it was populated while we waited for the lock
        val = cache.get(key)
        if val is not None:
            return val
            
        # Not in cache, fetch it
        val = await fetch_func()
        cache.set(key, val, expire=ttl)
        return val
