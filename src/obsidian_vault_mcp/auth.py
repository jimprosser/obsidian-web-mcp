"""Bearer token authentication middleware for the vault MCP server."""

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import VAULT_MCP_TOKEN

# Paths that don't require bearer auth (OAuth flow + health + RFC 9728 metadata)
_AUTH_EXEMPT_PATHS = {
    "/health",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
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


def _challenge_header(request: Request) -> dict[str, str]:
    """Build a WWW-Authenticate header pointing at the resource metadata endpoint
    so spec-compliant MCP clients can auto-discover the auth server (RFC 9728)."""
    base_url = str(request.base_url).rstrip("/")
    metadata_url = f"{base_url}/.well-known/oauth-protected-resource"
    return {
        "WWW-Authenticate": (
            f'Bearer realm="vault-mcp", '
            f'resource_metadata="{metadata_url}"'
        )
    }


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Validates Bearer tokens on all requests except OAuth and health endpoints."""

    async def dispatch(self, request: Request, call_next):
        # CORS preflight requests carry no credentials by design — the browser
        # uses the response to decide whether to send the real request. Returning
        # 401 here would prevent the real request from ever happening.
        if request.method == "OPTIONS":
            return await call_next(request)

        if request.url.path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)

        # RFC 9728 / RFC 8414 allow resource-specific suffixes on well-known
        # metadata paths (e.g. /.well-known/oauth-protected-resource/mcp).
        # Claude.ai's connector broker probes these and aborts silently if they 401.
        if request.url.path.startswith("/.well-known/"):
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
                headers=_challenge_header(request),
            )

        token = auth_header[7:]
        if not hmac.compare_digest(token, VAULT_MCP_TOKEN):
            return JSONResponse(
                {"error": "Invalid token"},
                status_code=401,
                headers=_challenge_header(request),
            )

        return await call_next(request)
