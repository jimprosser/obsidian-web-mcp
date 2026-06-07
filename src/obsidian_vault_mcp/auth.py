"""Bearer token authentication middleware for the vault MCP server."""

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import config
from .config import VAULT_MCP_TOKEN

# Paths that don't require bearer auth (OAuth flow + health)
_AUTH_EXEMPT_PATHS = {
    "/health",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/register",
}


def _www_authenticate(request: Request, error: str) -> str:
    """RFC 9728 challenge header pointing clients at the protected-resource metadata.

    Without it a 401 just looks like a failed request; with it, a spec-compliant MCP
    client (e.g. Claude Code, ChatGPT) knows to fetch the metadata and start the OAuth
    flow -- "Needs authentication" instead of "Failed to connect". The resource URL is
    derived from VAULT_MCP_PUBLIC_URL when set (otherwise request.base_url), matching the
    oauth_metadata / oauth_protected_resource endpoints. Pinning the public URL keeps a
    spoofed Host/X-Forwarded-Host header from pointing clients at an attacker's server.
    """
    base_url = config.advertised_base_url(str(request.base_url))
    resource_metadata = f"{base_url}/.well-known/oauth-protected-resource"
    return f'Bearer realm="mcp", resource_metadata="{resource_metadata}", error="{error}"'


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Validates Bearer tokens on all requests except OAuth and health endpoints."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path in _AUTH_EXEMPT_PATHS:
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
                headers={"WWW-Authenticate": _www_authenticate(request, "invalid_request")},
            )

        token = auth_header[7:]
        # Constant-time compare: avoid leaking the token via response timing (#2).
        if not hmac.compare_digest(token, VAULT_MCP_TOKEN):
            return JSONResponse(
                {"error": "Invalid token"},
                status_code=401,
                headers={"WWW-Authenticate": _www_authenticate(request, "invalid_token")},
            )

        return await call_next(request)
