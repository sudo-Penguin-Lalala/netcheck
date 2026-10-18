import os
import hashlib
import asyncio
import tempfile
from pathlib import Path
import diskcache
from typing import Callable, Any, Awaitable

def _resolve_cache_dir() -> str:
    env_dir = os.environ.get("CACHE_DIR")
    if env_dir:
        try:
            os.makedirs(env_dir, exist_ok=True)
            if os.access(env_dir, os.W_OK):
                return env_dir
        except (OSError, PermissionError):
            pass

    default_dir = "/data/netcheck-cache"
    try:
        if os.path.isdir(default_dir) and os.access(default_dir, os.W_OK):
            return default_dir
        if not os.path.exists(default_dir):
            os.makedirs(default_dir, exist_ok=True)
            return default_dir
    except (OSError, PermissionError):
        pass
    # Fallback for standard non-root / local dev environments
    user_cache = Path.home() / ".cache" / "netcheck"
    try:
        user_cache.mkdir(parents=True, exist_ok=True)
        if os.access(user_cache, os.W_OK):
            return str(user_cache)
    except (OSError, PermissionError):
        pass
    temp_dir = os.path.join(tempfile.gettempdir(), "netcheck-cache")
    try:
        os.makedirs(temp_dir, exist_ok=True)
    except (OSError, PermissionError):
        pass
    return temp_dir

CACHE_DIR = _resolve_cache_dir()
cache = diskcache.Cache(CACHE_DIR, disk=diskcache.JSONDisk)

_locks: dict[str, asyncio.Lock] = {}
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
    try:
        async with lock:
            # Check again in case it was populated while we waited for the lock
            val = cache.get(key)
            if val is not None:
                return val
                
            # Not in cache, fetch it
            val = await fetch_func()
            cache.set(key, val, expire=ttl)
            return val
    finally:
        # Clean up lock entry when no longer needed to prevent memory leak
        async with _locks_lock:
            if key in _locks and not lock.locked():
                _locks.pop(key, None)
