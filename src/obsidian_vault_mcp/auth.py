"""Bearer token authentication middleware for the vault MCP server."""

import hmac
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import config
from .config import VAULT_MCP_TOKEN
from .context import reset_request_context, set_request_context

# Paths that don't require bearer auth (OAuth flow + health)
_AUTH_EXEMPT_PATHS = {
    "/health",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/register",
}

# (method, path) pairs exempt from auth. The MCP spec 2025-06-18 probe on / must
# answer GET/HEAD without credentials. This is ONLY active when MCP is mounted off
# root (VAULT_MCP_PATH != "/"); when MCP is at root the transport owns GET/HEAD /
# and must stay fully authenticated, so the set is empty and behaviour is unchanged.
_AUTH_EXEMPT_METHOD_PATHS = (
    {("GET", "/"), ("HEAD", "/")} if config.VAULT_MCP_PATH != "/" else set()
)


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

        # Thread the authenticated principal (plus a request id and best-effort client
        # hint) to the tool layer for the audit log. The raw token never leaves this
        # context; audit.build_audit_record stores only its SHA-256 hash. client_id is a
        # User-Agent-derived hint -- it becomes a true per-client id if the static bearer
        # token is ever replaced with per-client tokens.
        client = request.headers.get("user-agent", "").strip()[:200] or None
        ctx_token = set_request_context(principal=token, request_id=uuid.uuid4().hex, client=client)
        try:
            return await call_next(request)
        finally:
            reset_request_context(ctx_token)
