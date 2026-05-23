"""slowapi limiter shared across routers."""
import os

from slowapi import Limiter
from slowapi.util import get_remote_address

RATE_LIMIT = os.environ.get("RATE_LIMIT", "10/minute")

# default_limits left empty — per-route decorators apply RATE_LIMIT explicitly
limiter = Limiter(key_func=get_remote_address, default_limits=[])
