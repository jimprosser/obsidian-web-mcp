"""Bearer token authentication middleware for the vault MCP server."""

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import VAULT_MCP_TOKEN

# Paths that don't require bearer auth (OAuth flow + health)
_AUTH_EXEMPT_PATHS = {
    "/health",
    "/.well-known/oauth-authorization-server",
    "/authorize",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/register",
}

# (method, path) pairs exempt from auth — used for the MCP spec probe on /,
# which must answer GET/HEAD without credentials while POST / stays authenticated.
_AUTH_EXEMPT_METHOD_PATHS = {
    ("GET", "/"),
    ("HEAD", "/"),
}


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Validates Bearer tokens on all requests except OAuth and health endpoints."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)

        if (request.method, request.url.path) in _AUTH_EXEMPT_METHOD_PATHS:
            return await call_next(request)

        if not VAULT_MCP_TOKEN:
            return JSONResponse(
                {"error": "Server misconfigured: no auth token set"},
                status_code=500,
            )

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                {"error": "Missing or malformed Authorization header"},
                status_code=401,
            )

        token = auth_header[7:]
        if not hmac.compare_digest(token, VAULT_MCP_TOKEN):
            return JSONResponse(
                {"error": "Invalid token"},
                status_code=401,
            )

        return await call_next(request)
