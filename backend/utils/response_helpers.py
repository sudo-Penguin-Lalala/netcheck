"""Safe parsing utilities for third-party API responses.

Provides defensive data extraction with fallbacks to prevent crashes when
external APIs (Globalping, WHOIS, IP lookup services) return unexpected
data structures, null values, or malformed types.
"""
from typing import Any, TypeVar

T = TypeVar('T')


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to int with fallback.

    Args:
        value: Value to convert (can be int, float, str, or None)
        default: Fallback value if conversion fails

    Returns:
        Integer value or default

    Examples:
        >>> safe_int("42")
        42
        >>> safe_int(None, -1)
        -1
        >>> safe_int("invalid", 0)
        0
    """
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float with fallback.

    Args:
        value: Value to convert (can be int, float, str, or None)
        default: Fallback value if conversion fails

    Returns:
        Float value or default

    Examples:
        >>> safe_float("3.14")
        3.14
        >>> safe_float(None, 0.0)
        0.0
        >>> safe_float("invalid", 0.0)
        0.0
    """
    if value is None:
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def safe_get(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Safely navigate nested dict with fallback.

    Args:
        data: Dictionary to navigate
        *keys: Sequence of keys to traverse
        default: Fallback value if any key is missing

    Returns:
        Value at nested path or default

    Examples:
        >>> d = {"a": {"b": {"c": 42}}}
        >>> safe_get(d, "a", "b", "c")
        42
        >>> safe_get(d, "a", "x", "y", default="missing")
        "missing"
    """
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def safe_list(value: Any, default: list | None = None) -> list:
    """Ensure value is a list, with fallback.

    Args:
        value: Value to validate as list
        default: Fallback list if validation fails (defaults to [])

    Returns:
        List value or default

    Examples:
        >>> safe_list([1, 2, 3])
        [1, 2, 3]
        >>> safe_list(None)
        []
        >>> safe_list("not a list")
        []
    """
    if default is None:
        default = []
    if isinstance(value, list):
        return value
    return default


def extract_first_globalping_result(body: dict[str, Any]) -> dict[str, Any]:
    """Extract first result from Globalping API response with safety.

    Globalping returns: {"results": [{"result": {...}, "probe": {...}}]}
    This safely extracts results[0].result with proper fallbacks.

    Args:
        body: Globalping API response body

    Returns:
        First result dict or empty dict if not found
    """
    results = safe_list(body.get("results"))
    if not results:
        return {}
    first = results[0] if isinstance(results[0], dict) else {}
    return safe_get(first, "result", default={}) or {}


def api_error(status: int, code: str, message: str) -> dict[str, Any]:
    """Construct standardized API error response.

    Args:
        status: HTTP status code
        code: Machine-readable error code (e.g., "bad_input")
        message: Human-readable error message

    Returns:
        Error response dict

    Examples:
        >>> api_error(400, "bad_input", "Invalid IP address")
        {"error": "bad_input", "message": "Invalid IP address"}
    """
    return {"error": code, "message": message}
