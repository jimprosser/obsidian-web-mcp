"""Bearer token authentication middleware for the vault MCP server."""

import hashlib
import hmac
import re
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

# The signed direct upload is the one exemption that is neither a fixed path nor a
# probe: POST to exactly one id segment under /upload. The id alphabet and the single
# segment are part of the rule, so /upload, /upload/a/b, or a GET on an upload URL all
# still need a bearer token. The URL's HMAC signature is the authorization; the route
# validates it before reading any body bytes.
_SIGNED_UPLOAD_PATH = re.compile(r"/upload/[A-Za-z0-9-]{1,64}")


def is_signed_upload_request(method: str, path: str) -> bool:
    """Whether this is the one request shape the signed upload route serves tokenless.

    False whenever the feature is off, so a server without VAULT_UPLOAD_URL_SECRET has no
    bearer-exempt write path at all.
    """
    if not config.signed_upload_enabled():
        return False
    return method == "POST" and _SIGNED_UPLOAD_PATH.fullmatch(path) is not None


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


def _master_matches(token: str) -> bool:
    """Compare fixed-length digests so token length does not affect comparison."""
    if not VAULT_MCP_TOKEN:
        return False
    candidate = hashlib.sha256(token.encode("utf-8")).digest()
    configured = hashlib.sha256(VAULT_MCP_TOKEN.encode("utf-8")).digest()
    return hmac.compare_digest(candidate, configured)


def _authenticate_bearer(request: Request, token: str) -> str | None:
    """Return the OAuth client id for a valid per-client token, None for master.

    Returns None for the master bearer and raises ValueError for anything that is
    neither the master bearer nor a valid, unrevoked, unexpired per-client token
    bound to this server's resource identifier.
    """
    if _master_matches(token):
        return None
    if not token.startswith("v1."):
        raise ValueError("invalid token")

    from .oauth import canonical_resource, get_oauth_state

    metadata = get_oauth_state().lookup_access_token(token)
    if metadata is None or metadata.resource != canonical_resource(request):
        raise ValueError("invalid token")
    return metadata.client_id


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Validates Bearer tokens on all requests except OAuth and health endpoints."""

    async def dispatch(self, request: Request, call_next):
        # The decoded ASGI path, not request.url.path. The latter is parsed back out of a
        # URL string, so an encoded "?" or "#" truncates it: "/health%3F/x" would read as
        # the exempt "/health" here while the router dispatched "/health?/x".
        path = request.scope["path"]

        if path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)

        if (request.method, path) in _AUTH_EXEMPT_METHOD_PATHS:
            return await call_next(request)

        if is_signed_upload_request(request.method, path):
            return await call_next(request)

        if not VAULT_MCP_TOKEN:
            return JSONResponse(
                {"error": "Server misconfigured: no auth token set"},
                status_code=500,
            )

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer ") or not auth_header[7:]:
            return JSONResponse(
                {"error": "Missing or malformed Authorization header"},
                status_code=401,
                headers={"WWW-Authenticate": _www_authenticate(request, "invalid_request")},
            )

        token = auth_header[7:]
        try:
            # None means the master bearer; a string is the per-client OAuth id.
            oauth_client_id = _authenticate_bearer(request, token)
        except ValueError:
            # Constant-time paths inside; a distinct message would leak which
            # credential class failed and help an attacker enumerate tokens (#2).
            return JSONResponse(
                {"error": "Invalid token"},
                status_code=401,
                headers={"WWW-Authenticate": _www_authenticate(request, "invalid_token")},
            )

        # Thread the authenticated principal (plus a request id and client hint) to the
        # tool layer for the audit log. The raw token never leaves this context;
        # audit.build_audit_record stores only its SHA-256 hash. Per-client OAuth
        # tokens carry the real client_id; the master bearer keeps the legacy
        # User-Agent-derived hint.
        client = oauth_client_id or request.headers.get("user-agent", "").strip()[:200] or None
        ctx_token = set_request_context(principal=token, request_id=uuid.uuid4().hex, client=client)
        try:
            return await call_next(request)
        finally:
            reset_request_context(ctx_token)
