"""Request hardening for the Barista HTTP server.

The API controls a physical appliance, so it must not be reachable by other
websites (CSRF / DNS rebinding) or, unless explicitly opted in, by other hosts.
"""

import hmac
import os
from typing import Optional
from urllib.parse import urlsplit

from aiohttp import web

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
MAX_QUANTITY_ML = 500
PROFILE_RANGE = (1, 4)


def is_loopback(host: str) -> bool:
    return host in LOOPBACK_HOSTS


def get_token(cli_token: Optional[str] = None) -> Optional[str]:
    return cli_token or os.environ.get("BARISTA_TOKEN") or None


def _hostname(netloc: str) -> str:
    return (urlsplit("//" + netloc).hostname or "").lower()


def _json_error(message: str, status: int) -> web.Response:
    return web.json_response({"error": message}, status=status)


def make_security_middleware(bind_host: str, token: Optional[str]):
    """Build a middleware enforcing Host/Origin checks, JSON bodies and an optional token."""

    @web.middleware
    async def security_middleware(request: web.Request, handler):
        # DNS rebinding: when only reachable locally, insist on a local Host header.
        if is_loopback(bind_host) and _hostname(request.host) not in LOOPBACK_HOSTS:
            return _json_error("Forbidden host", 403)

        # CSRF: browsers always send Origin on cross-site POSTs; it must match this server.
        origin = request.headers.get("Origin")
        if origin and origin != "null" and _hostname(urlsplit(origin).netloc) != _hostname(request.host):
            return _json_error("Cross-origin requests are not allowed", 403)
        if origin == "null":
            return _json_error("Cross-origin requests are not allowed", 403)

        if request.method not in ("GET", "HEAD") and request.can_read_body:
            if request.content_type != "application/json":
                return _json_error("Content-Type must be application/json", 415)

        # The UI shell is public; everything under /api requires the token when one is set.
        if token and request.path.startswith("/api"):
            auth = request.headers.get("Authorization", "")
            supplied = auth[7:] if auth.startswith("Bearer ") else request.headers.get("X-Barista-Token", "")
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                return _json_error("Unauthorized", 401)

        return await handler(request)

    return security_middleware


class InvalidValue(ValueError):
    pass


def int_in_range(value, name: str, lo: int, hi: int) -> int:
    """Return value as an int in [lo, hi] or raise InvalidValue (bools and floats are rejected)."""
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise InvalidValue(f"{name} must be an integer between {lo} and {hi}")
    return value
