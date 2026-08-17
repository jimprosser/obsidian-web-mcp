"""Bearer authentication and principal binding for the vault MCP server."""

from __future__ import annotations

import hashlib
import hmac
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import config
from .config import VAULT_MCP_TOKEN
from .context import (
    AuthenticatedPrincipal,
    reset_request_context,
    set_request_context,
)
from .oauth_state import (
    LEGACY_FULL,
    VAULT_READONLY_CAPABILITIES,
    VAULT_READONLY_V1,
)

_AUTH_EXEMPT_PATHS = {
    "/health",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/register",
}

_AUTH_EXEMPT_METHOD_PATHS = (
    {("GET", "/"), ("HEAD", "/")} if config.VAULT_MCP_PATH != "/" else set()
)


def _www_authenticate(request: Request, error: str) -> str:
    """Build an RFC 9728 challenge pinned to the advertised resource."""
    base_url = config.advertised_base_url(str(request.base_url))
    resource_metadata = f"{base_url}/.well-known/oauth-protected-resource"
    return (
        f'Bearer realm="mcp", resource_metadata="{resource_metadata}", error="{error}"'
    )


def _credential_digest(token: str) -> str:
    """Return a stable audit identifier without retaining the bearer."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _master_matches(token: str) -> bool:
    """Compare fixed-length digests so token length does not affect comparison."""
    if not VAULT_MCP_TOKEN:
        return False
    candidate = hashlib.sha256(token.encode("utf-8")).digest()
    configured = hashlib.sha256(VAULT_MCP_TOKEN.encode("utf-8")).digest()
    return hmac.compare_digest(candidate, configured)


def _canonical_resource(request: Request) -> str:
    return config.advertised_base_url(str(request.base_url)).rstrip("/")


def _authenticate_bearer(
    request: Request,
    token: str,
) -> AuthenticatedPrincipal | None:
    credential_id = _credential_digest(token)
    if _master_matches(token):
        return AuthenticatedPrincipal(
            principal_id="master",
            credential_id=credential_id,
            client_id=None,
            policy=LEGACY_FULL,
            capabilities=frozenset(),
            full_access=True,
        )

    if not token.startswith("v1."):
        return None

    from .oauth import get_oauth_state

    metadata = get_oauth_state().lookup_access_token(token)
    if metadata is None or metadata.resource != _canonical_resource(request):
        return None

    capabilities = frozenset(metadata.capabilities)
    if metadata.policy == LEGACY_FULL:
        if capabilities:
            return None
        full_access = True
    elif metadata.policy == VAULT_READONLY_V1:
        if capabilities != frozenset(VAULT_READONLY_CAPABILITIES):
            return None
        full_access = False
    else:
        return None

    return AuthenticatedPrincipal(
        principal_id=f"oauth:{metadata.client_id}",
        credential_id=credential_id,
        client_id=metadata.client_id,
        policy=metadata.policy,
        capabilities=capabilities,
        full_access=full_access,
    )


def _auth_error(
    request: Request,
    *,
    message: str,
    status_code: int,
    error: str,
) -> JSONResponse:
    return JSONResponse(
        {"error": message},
        status_code=status_code,
        headers={"WWW-Authenticate": _www_authenticate(request, error)},
    )


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Authenticate master and OAuth bearers through one fail-closed path."""

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
        if not auth_header.startswith("Bearer ") or not auth_header[7:]:
            return _auth_error(
                request,
                message="Missing or malformed Authorization header",
                status_code=401,
                error="invalid_request",
            )

        principal = _authenticate_bearer(request, auth_header[7:])
        if principal is None:
            return _auth_error(
                request,
                message="Invalid token",
                status_code=401,
                error="invalid_token",
            )

        if not principal.full_access and request.url.path != config.VAULT_MCP_PATH:
            return _auth_error(
                request,
                message="Insufficient scope",
                status_code=403,
                error="insufficient_scope",
            )

        ctx_token = set_request_context(
            principal=principal,
            request_id=uuid.uuid4().hex,
        )
        try:
            return await call_next(request)
        finally:
            reset_request_context(ctx_token)
