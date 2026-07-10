"""Cloudflare Access authentication mode (optional, opt-in).

When VAULT_MCP_CF_ACCESS_TEAM_DOMAIN and VAULT_MCP_CF_ACCESS_AUD are BOTH set, the
server trusts Cloudflare Access to authenticate callers at its edge and verifies the
signed `Cf-Access-Jwt-Assertion` header Cloudflare injects on every request it forwards
through the tunnel. When either is unset the mode is OFF and this module's middleware is
never attached.

Fail closed: any verification failure -- missing/malformed/expired token, bad signature,
wrong audience/issuer, or an unreachable/unparseable key set -- is a 401. PyJWT and
cryptography are imported lazily so the OFF path never touches them.
"""

from __future__ import annotations

import logging
import threading
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import config
from .context import reset_request_context, set_request_context

logger = logging.getLogger(__name__)

# The header Cloudflare Access injects on every request it forwards through the tunnel.
_CF_ACCESS_HEADER = "Cf-Access-Jwt-Assertion"

# Only the liveness probe is exempt; every other path requires a valid token.
_CF_EXEMPT_PATHS = {"/health"}

# Lazily-built PyJWKClient, cached across requests (see _get_jwk_client).
_jwk_client = None
_jwk_client_lock = threading.Lock()


def _normalize_team_domain(raw: str) -> str:
    """Return the bare Cloudflare team domain (no scheme, no trailing slash).

    Accepts "myteam", "myteam.cloudflareaccess.com", or a full URL. A bare team name
    (no dot) gets ".cloudflareaccess.com" appended.
    """
    domain = (raw or "").strip()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.strip("/").strip()
    if not domain:
        return ""
    if "." not in domain:
        domain = f"{domain}.cloudflareaccess.com"
    return domain


def team_domain() -> str:
    """The normalized team domain, or "" when unset."""
    return _normalize_team_domain(config.VAULT_MCP_CF_ACCESS_TEAM_DOMAIN)


def _aud() -> str:
    return (config.VAULT_MCP_CF_ACCESS_AUD or "").strip()


def cf_access_enabled() -> bool:
    """True only when BOTH the team domain and the AUD are configured (both-or-neither)."""
    return bool(team_domain()) and bool(_aud())


def issuer() -> str:
    """The expected JWT issuer, "https://<team-domain>"."""
    return f"https://{team_domain()}"


def certs_url() -> str:
    """Cloudflare's JWKS endpoint for the configured team."""
    return f"https://{team_domain()}/cdn-cgi/access/certs"


# A conservative DNS-hostname shape: dot-separated labels of letters/digits/hyphens, no
# leading/trailing hyphen per label. Cloudflare team domains are always
# <team>.cloudflareaccess.com, so this is deliberately strict -- it exists to catch a
# typo, not to accept every RFC-legal name.
_HOSTNAME_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"


def validate_cf_access_config() -> None:
    """When CF Access mode is on, reject a team domain that isn't a plausible hostname.

    A typo'd VAULT_MCP_CF_ACCESS_TEAM_DOMAIN would otherwise boot a server that
    fail-closes every request (safe, but silently broken) -- so catch a malformed value
    at startup with a clear message, matching how VAULT_MCP_PATH is validated. This is a
    pure FORMAT check: connectivity to the JWKS endpoint is NOT probed here (warm_jwks
    stays non-fatal so a transient Cloudflare blip can't wedge startup). A no-op unless
    both settings are set (a half-config is mode-off and only warns, in serve()).
    """
    import re

    if not cf_access_enabled():
        return
    domain = team_domain()
    if not re.fullmatch(rf"{_HOSTNAME_LABEL}(?:\.{_HOSTNAME_LABEL})+", domain):
        raise ValueError(
            "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN does not look like a valid hostname "
            f"(normalized to {domain!r}); expected e.g. 'myteam.cloudflareaccess.com'"
        )


class CfAccessError(Exception):
    """Any failure to verify a Cloudflare Access token. Always maps to a 401."""


def require_dependencies() -> None:
    """Import the JWT libraries, raising CfAccessError with install guidance if absent.

    Called once at startup so a mode-on server with the extra missing fails CLOSED with a
    clear message, instead of 401ing every request forever at runtime.
    """
    try:
        import cryptography  # noqa: F401
        import jwt  # noqa: F401
    except Exception as e:
        raise CfAccessError(
            "Cloudflare Access mode is enabled but its dependencies are missing. "
            "Install them with: pip install 'obsidian-web-mcp[cloudflare-access]'"
        ) from e


def _get_jwk_client():
    """Return a cached PyJWKClient for the configured team's JWKS endpoint.

    Built on first use (not at import) so the OFF path never imports PyJWT. PyJWKClient
    caches fetched keys in-process and refreshes on an unknown kid, so verification does
    not hit Cloudflare per request.

    Thread-safe: double-checked locking ensures only one PyJWKClient is ever constructed
    even when concurrent requests race on the first call.
    """
    global _jwk_client
    if _jwk_client is None:
        with _jwk_client_lock:
            if _jwk_client is None:
                from jwt import PyJWKClient
                _jwk_client = PyJWKClient(certs_url())
    return _jwk_client


def verify_access_token(header_value: str) -> dict:
    """Verify a Cf-Access-Jwt-Assertion value; return its claims or raise CfAccessError.

    Enforces signature (RS256, against Cloudflare's published keys), expiry, audience
    (AUD), and issuer. Every failure path -- missing/empty header, malformed token,
    unreachable JWKS, bad signature, expired, wrong aud/iss -- raises CfAccessError.
    """
    token = (header_value or "").strip()
    if not token:
        raise CfAccessError("missing Cf-Access-Jwt-Assertion header")

    import jwt

    try:
        signing_key = _get_jwk_client().get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=_aud(),
            issuer=issuer(),
            options={"require": ["exp", "iss", "aud"]},
        )
    except Exception as e:
        # Covers PyJWKClientError (unreachable/unparseable JWKS) and every
        # InvalidTokenError subclass (expired, bad signature, wrong aud/iss, malformed,
        # missing required claim). Fail closed on all of them.
        raise CfAccessError(f"token verification failed: {type(e).__name__}") from e

    return claims


def warm_jwks() -> None:
    """Best-effort prefetch of the signing keys at startup. Never raises.

    Per-request verification is fail-closed regardless; this only surfaces an obviously
    broken team domain early in the logs instead of on the first real request.
    """
    try:
        _get_jwk_client().get_signing_keys()
    except Exception as e:
        logger.warning(
            "Could not prefetch Cloudflare Access signing keys: %s", type(e).__name__
        )


class CloudflareAccessMiddleware(BaseHTTPMiddleware):
    """Validate the Cf-Access-Jwt-Assertion header on every request except /health.

    Fail closed: any CfAccessError -> 401. No WWW-Authenticate challenge is emitted --
    that header bootstraps the app's OWN OAuth flow, which is not served in this mode, so
    advertising it would point clients at a nonexistent auth surface.
    """

    async def dispatch(self, request: Request, call_next):
        if request.url.path in _CF_EXEMPT_PATHS:
            return await call_next(request)

        try:
            claims = verify_access_token(request.headers.get(_CF_ACCESS_HEADER, ""))
        except CfAccessError:
            return JSONResponse(
                {"error": "Invalid or missing Cloudflare Access token"},
                status_code=401,
            )

        # Prefer the human email; fall back to the opaque subject for service tokens so
        # the audit principal is never empty for a validly-authenticated request. This
        # only labels the audit record -- it has no bearing on the auth decision above.
        principal = claims.get("email") or claims.get("sub") or None
        ctx_token = set_request_context(
            principal=principal, request_id=uuid.uuid4().hex, client=principal
        )
        try:
            return await call_next(request)
        finally:
            reset_request_context(ctx_token)
