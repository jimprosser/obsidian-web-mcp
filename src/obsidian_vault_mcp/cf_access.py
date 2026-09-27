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
import urllib.request
import uuid

from starlette.concurrency import run_in_threadpool
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
    """Fail startup on a broken Cloudflare Access configuration.

    Two failure shapes, both caught here so a bad value stops the boot with a clear
    message, matching how VAULT_MCP_PATH is validated:

    - HALF-CONFIG: exactly one of the two settings set. The operator meant to enable
      the mode, so silently booting bearer+OAuth instead would swap the auth surface
      out from under them -- the same "silently broken server" a malformed value causes.
    - MALFORMED DOMAIN: mode on, but the team domain isn't a plausible hostname. The
      error names the setting and the expected format WITHOUT echoing the value: a
      pasted URL can carry credentials, and this message lands in the startup log.

    This is a pure FORMAT check: connectivity to the JWKS endpoint is NOT probed here
    (warm_jwks stays non-fatal so a transient Cloudflare blip can't wedge startup).
    A no-op when neither setting is set.
    """
    import re

    team_set = bool(team_domain())
    aud_set = bool(_aud())
    if not team_set and not aud_set:
        return
    if team_set != aud_set:
        only = "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN" if team_set else "VAULT_MCP_CF_ACCESS_AUD"
        raise ValueError(
            "Cloudflare Access mode requires BOTH VAULT_MCP_CF_ACCESS_TEAM_DOMAIN and "
            f"VAULT_MCP_CF_ACCESS_AUD; only {only} is set. Set both to enable the mode, "
            "or neither to run with bearer auth + OAuth."
        )
    if not re.fullmatch(rf"{_HOSTNAME_LABEL}(?:\.{_HOSTNAME_LABEL})+", team_domain()):
        raise ValueError(
            "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN does not look like a valid hostname; "
            "expected a Cloudflare team domain like 'myteam.cloudflareaccess.com' "
            "(value not shown in case it carries credentials)"
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


# Far above any real Cloudflare key set (a handful of RSA keys is a few KB); the cap
# exists so a compromised or misdirected endpoint cannot feed an unbounded body into
# json.loads, which PyJWKClient's own fetch would accept.
_JWKS_MAX_BYTES = 1 << 20


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects on the JWKS fetch. Returning None makes urllib raise."""

    def redirect_request(self, *args, **kwargs):
        return None


def _build_jwk_client(uri: str):
    """A PyJWKClient whose HTTP fetch is bounded: no redirects, response size capped.

    Only fetch_data is overridden -- get_jwk_set validates and caches whatever a
    subclass's fetch_data returns, so the cache-preserve-on-error and unknown-kid
    cooldown semantics of the parent are kept.
    """
    from jwt import PyJWKClient
    from jwt.exceptions import PyJWKClientConnectionError

    class _BoundedPyJWKClient(PyJWKClient):
        def fetch_data(self):
            import json
            import time

            request = urllib.request.Request(url=self.uri, headers=self.headers)
            opener = urllib.request.build_opener(_NoRedirect)
            try:
                with opener.open(request, timeout=self.timeout) as response:
                    raw = response.read(_JWKS_MAX_BYTES + 1)
            except Exception as e:
                raise PyJWKClientConnectionError(
                    f"Failed to fetch the JWKS endpoint: {type(e).__name__}"
                ) from e
            if len(raw) > _JWKS_MAX_BYTES:
                raise PyJWKClientConnectionError(
                    f"JWKS response exceeded the {_JWKS_MAX_BYTES}-byte cap"
                )
            jwk_set = json.loads(raw)
            # The parent's fetch_data stamps the fetch time that rate-limits
            # unknown-kid refreshes; keep that behavior (guarded: internal attr).
            if hasattr(self, "_last_successful_fetch"):
                self._last_successful_fetch = time.monotonic()
            return jwk_set

    return _BoundedPyJWKClient(uri)


def _get_jwk_client():
    """Return a cached JWK client for the configured team's JWKS endpoint.

    Built on first use (not at import) so the OFF path never imports PyJWT. The client
    caches fetched keys in-process and refreshes on an unknown kid, so verification does
    not hit Cloudflare per request.

    Thread-safe: double-checked locking ensures only one client is ever constructed
    even when concurrent requests race on the first call.
    """
    global _jwk_client
    if _jwk_client is None:
        with _jwk_client_lock:
            if _jwk_client is None:
                _jwk_client = _build_jwk_client(certs_url())
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
            # verify_access_token can block on the JWKS fetch (urlopen, up to 30s);
            # run it in a worker thread so a slow fetch cannot stall the event loop
            # and every other in-flight request with it.
            claims = await run_in_threadpool(
                verify_access_token, request.headers.get(_CF_ACCESS_HEADER, "")
            )
        except CfAccessError:
            return JSONResponse(
                {"error": "Invalid or missing Cloudflare Access token"},
                status_code=401,
            )

        # Prefer the human email; service-token JWTs carry sub: "" with the identity
        # in common_name, so try that before the subject -- the audit principal must
        # never be empty for a validly-authenticated request. This only labels the
        # audit record; it has no bearing on the auth decision above.
        principal = claims.get("email") or claims.get("common_name") or claims.get("sub") or None
        ctx_token = set_request_context(
            principal=principal, request_id=uuid.uuid4().hex, client=principal
        )
        try:
            return await call_next(request)
        finally:
            reset_request_context(ctx_token)
