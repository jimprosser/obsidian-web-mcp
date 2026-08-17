"""OAuth 2.0 endpoints backed by durable per-client lifecycle state."""

from __future__ import annotations

import hashlib
import hmac
import html
import logging
import urllib.parse
from collections.abc import Mapping
from typing import Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from . import config
from .oauth_state import (
    LEGACY_FULL,
    REAUTHORIZATION_REQUIRED,
    InvalidClient,
    InvalidGrant,
    InvalidTarget,
    OAuthState,
)

logger = logging.getLogger(__name__)

_oauth_state: OAuthState | None = None


def _text_matches(candidate: str, expected: str) -> bool:
    """Compare arbitrary Unicode text through fixed-length byte digests."""
    candidate_digest = hashlib.sha256(candidate.encode("utf-8")).digest()
    expected_digest = hashlib.sha256(expected.encode("utf-8")).digest()
    return hmac.compare_digest(candidate_digest, expected_digest)


def _static_client_authenticator(client_id: str, client_secret: str) -> bool:
    return bool(
        config.VAULT_OAUTH_CLIENT_ID
        and config.VAULT_OAUTH_CLIENT_SECRET
        and _text_matches(client_id, config.VAULT_OAUTH_CLIENT_ID)
        and _text_matches(client_secret, config.VAULT_OAUTH_CLIENT_SECRET)
    )


def initialize_oauth_state() -> OAuthState:
    """Open durable OAuth state and ensure the configured static identity."""
    global _oauth_state
    configured_path = config.VAULT_OAUTH_STATE_PATH.expanduser().absolute()
    if _oauth_state is not None and _oauth_state.path != configured_path:
        close_oauth_state()
    if _oauth_state is None:
        state = OAuthState(
            configured_path,
            vault_path=config.VAULT_PATH,
            legacy_path=config.OAUTH_CLIENTS_PATH,
            approved_legacy_client_ids=(config.VAULT_OAUTH_APPROVED_LEGACY_CLIENT_IDS),
            access_token_ttl_seconds=(config.oauth_access_token_ttl_seconds()),
            static_client_authenticator=_static_client_authenticator,
        )
        try:
            state.migrate_legacy()
            if config.VAULT_OAUTH_CLIENT_ID:
                state.ensure_static_client(
                    config.VAULT_OAUTH_CLIENT_ID,
                    config.VAULT_OAUTH_REDIRECT_URIS,
                    policy=LEGACY_FULL,
                    capabilities=(),
                )
        except BaseException:
            state.close()
            raise
        _oauth_state = state
    return _oauth_state


def get_oauth_state() -> OAuthState:
    """Return the process state handle, opening it lazily when necessary."""
    return initialize_oauth_state()


def close_oauth_state() -> None:
    """Close the process state handle without changing durable state."""
    global _oauth_state
    if _oauth_state is not None:
        _oauth_state.close()
        _oauth_state = None


def _canonical_resource(request: Request) -> str:
    return config.advertised_base_url(str(request.base_url)).rstrip("/")


async def oauth_metadata(request: Request) -> JSONResponse:
    """OAuth authorization-server metadata (RFC 8414)."""
    base = _canonical_resource(request)
    return JSONResponse(
        {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",
            "resource": base,
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "client_credentials",
            ],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
        }
    )


async def oauth_protected_resource(request: Request) -> JSONResponse:
    """Protected-resource metadata (RFC 9728)."""
    base = _canonical_resource(request)
    return JSONResponse(
        {
            "resource": base,
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
        }
    )


def _request_parameters(
    request: Request, form: Mapping[str, Any] | None
) -> dict[str, str]:
    source: Mapping[str, Any] = form if form is not None else request.query_params
    names = (
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "resource",
    )
    params = {name: str(source.get(name, "") or "") for name in names}
    if not params["code_challenge_method"]:
        params["code_challenge_method"] = "S256"
    return params


def _validate_authorization_request(request: Request, params: Mapping[str, str]):
    if params["response_type"] != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
    state = get_oauth_state()
    client = state.get_client(params["client_id"])
    if client is None or client.revoked_at is not None:
        return JSONResponse({"error": "invalid_client"}, status_code=400)
    if not state.client_redirect_uri_allowed(
        params["client_id"], params["redirect_uri"]
    ):
        return JSONResponse(
            {
                "error": "invalid_request",
                "error_description": "Invalid or unregistered redirect_uri",
            },
            status_code=400,
        )
    if not params["code_challenge"] or params["code_challenge_method"] != "S256":
        return JSONResponse(
            {
                "error": "invalid_request",
                "error_description": "PKCE with S256 is required",
            },
            status_code=400,
        )
    if params["resource"] != _canonical_resource(request):
        return JSONResponse(
            {
                "error": "invalid_target",
                "error_description": "resource must match this server",
            },
            status_code=400,
        )
    return None


def _login_configured() -> bool:
    return bool(config.VAULT_OAUTH_PASSWORD)


def _check_credentials(username: str, password: str) -> bool:
    expected_username = config.VAULT_OAUTH_USERNAME or "obsidian"
    return bool(
        _login_configured()
        and _text_matches(username, expected_username)
        and _text_matches(password, config.VAULT_OAUTH_PASSWORD)
    )


def _login_form(
    params: Mapping[str, str],
    *,
    client_name: str,
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    hidden = "\n".join(
        f'<input type="hidden" name="{html.escape(name)}" '
        f'value="{html.escape(value, quote=True)}">'
        for name, value in params.items()
    )
    error_html = f'<p role="alert">{html.escape(error)}</p>' if error else ""
    client_name_html = html.escape(client_name)
    redirect_uri_html = html.escape(params["redirect_uri"])
    content = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Authorize Obsidian Vault MCP</title></head>
<body>
  <main>
    <h1>Authorize Obsidian Vault MCP</h1>
    <p>Client: <strong>{client_name_html}</strong></p>
    <p>Redirect URI: <code>{redirect_uri_html}</code></p>
    {error_html}
    <form method="post" action="/oauth/authorize">
      {hidden}
      <label>Username <input name="username" autocomplete="username"></label>
      <label>Password <input name="password" type="password" autocomplete="current-password"></label>
      <button type="submit">Authorize</button>
    </form>
  </main>
</body>
</html>"""
    return HTMLResponse(content, status_code=status_code)


def _login_misconfigured() -> HTMLResponse:
    return HTMLResponse(
        "OAuth login is not configured; set VAULT_OAUTH_PASSWORD.",
        status_code=503,
    )


async def oauth_authorize(request: Request):
    """Validate a request, authenticate the human, and issue a durable code."""
    form = await request.form() if request.method == "POST" else None
    params = _request_parameters(request, form)
    invalid = _validate_authorization_request(request, params)
    if invalid is not None:
        return invalid
    if not _login_configured():
        logger.error("OAuth authorization refused: login is not configured")
        return _login_misconfigured()
    state = get_oauth_state()
    client = state.get_client(params["client_id"])
    assert client is not None
    if request.method == "GET":
        return _login_form(params, client_name=client.client_name)

    assert form is not None
    username = str(form.get("username", "") or "")
    password = str(form.get("password", "") or "")
    if not _check_credentials(username, password):
        logger.warning("OAuth login failed")
        return _login_form(
            params,
            client_name=client.client_name,
            error="Invalid username or password",
            status_code=401,
        )

    requires_reauthorization = client.policy == REAUTHORIZATION_REQUIRED
    code = state.issue_authorization_code(
        client_id=client.client_id,
        redirect_uri=params["redirect_uri"],
        code_challenge=params["code_challenge"],
        resource=params["resource"],
        fresh_reauthorization=requires_reauthorization,
    )
    query = {"code": code}
    if params["state"]:
        query["state"] = params["state"]
    separator = "&" if "?" in params["redirect_uri"] else "?"
    location = f"{params['redirect_uri']}{separator}{urllib.parse.urlencode(query)}"
    logger.info("OAuth authorization code issued")
    return RedirectResponse(location, status_code=302)


def _token_response(issued) -> JSONResponse:
    expires_in = max(0, int(issued.token.expires_at - issued.token.issued_at))
    return JSONResponse(
        {
            "access_token": issued.access_token,
            "token_type": "bearer",
            "expires_in": expires_in,
        }
    )


def _oauth_error(
    error: str,
    description: str,
    *,
    status_code: int = 400,
) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
    )


async def _handle_authorization_code(
    request: Request, form: Mapping[str, Any]
) -> JSONResponse:
    fields = {
        name: str(form.get(name, "") or "")
        for name in (
            "code",
            "client_id",
            "client_secret",
            "redirect_uri",
            "code_verifier",
            "resource",
        )
    }
    if not all(fields.values()):
        return _oauth_error(
            "invalid_request",
            "code, client_id, client_secret, redirect_uri, code_verifier, "
            "and resource are required",
        )
    try:
        issued = get_oauth_state().redeem_authorization_code(**fields)
    except InvalidClient:
        return _oauth_error(
            "invalid_client", "client authentication failed", status_code=401
        )
    except InvalidTarget:
        return _oauth_error("invalid_target", "resource does not match authorization")
    except InvalidGrant:
        return _oauth_error("invalid_grant", "authorization code is invalid")
    return _token_response(issued)


async def _handle_client_credentials(
    request: Request, form: Mapping[str, Any]
) -> JSONResponse:
    client_id = str(form.get("client_id", "") or "")
    client_secret = str(form.get("client_secret", "") or "")
    resource = str(form.get("resource", "") or "")
    canonical_resource = _canonical_resource(request)
    if resource != canonical_resource:
        return _oauth_error("invalid_target", "resource must match this server")
    state = get_oauth_state()
    client = state.get_client(client_id)
    if (
        client is None
        or not client.is_static
        or not state.verify_client_secret(client_id, client_secret)
    ):
        return _oauth_error(
            "invalid_client", "client authentication failed", status_code=401
        )
    try:
        issued = state.issue_access_token(
            client_id=client_id,
            resource=resource,
        )
    except InvalidClient:
        return _oauth_error(
            "invalid_client", "client authentication failed", status_code=401
        )
    return _token_response(issued)


async def oauth_token(request: Request) -> JSONResponse:
    """Exchange a code or static client credentials for an opaque token."""
    form = await request.form()
    grant_type = str(form.get("grant_type", "") or "")
    if grant_type == "authorization_code":
        return await _handle_authorization_code(request, form)
    if grant_type == "client_credentials":
        return await _handle_client_credentials(request, form)
    return _oauth_error("unsupported_grant_type", "unsupported grant_type")


def _valid_redirect_uri(uri: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(uri)
    except ValueError:
        return False
    if parsed.scheme == "https":
        return bool(parsed.netloc)
    if parsed.scheme != "http":
        return False
    return parsed.hostname in {"localhost", "127.0.0.1", "::1"}


async def oauth_register(request: Request) -> JSONResponse:
    """Register a confidential authorization-code client."""
    try:
        body = await request.json()
    except (ValueError, TypeError):
        return _oauth_error("invalid_client_metadata", "invalid JSON body")
    if not isinstance(body, dict):
        return _oauth_error(
            "invalid_client_metadata", "registration body must be an object"
        )
    raw_redirects = body.get("redirect_uris", [])
    if not isinstance(raw_redirects, list):
        return _oauth_error("invalid_client_metadata", "redirect_uris must be an array")
    if not raw_redirects or any(
        not isinstance(uri, str) or not _valid_redirect_uri(uri)
        for uri in raw_redirects
    ):
        return _oauth_error(
            "invalid_redirect_uri",
            "redirect_uris must contain only HTTPS or loopback HTTP URIs",
        )
    redirect_uris = list(dict.fromkeys(raw_redirects))
    client_name = body.get("client_name", "Obsidian Vault MCP Client")
    if not isinstance(client_name, str):
        return _oauth_error("invalid_client_metadata", "client_name must be a string")
    registered = get_oauth_state().register_client(
        redirect_uris, client_name=client_name
    )
    return JSONResponse(
        {
            "client_id": registered.client.client_id,
            "client_secret": registered.client_secret,
            "client_name": registered.client.client_name,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "redirect_uris": list(registered.client.redirect_uris),
            "token_endpoint_auth_method": "client_secret_post",
        },
        status_code=201,
    )


oauth_routes = [
    Route(
        "/.well-known/oauth-authorization-server",
        oauth_metadata,
        methods=["GET"],
    ),
    Route(
        "/.well-known/oauth-protected-resource",
        oauth_protected_resource,
        methods=["GET"],
    ),
    Route("/oauth/authorize", oauth_authorize, methods=["GET", "POST"]),
    Route("/oauth/token", oauth_token, methods=["POST"]),
    Route("/oauth/register", oauth_register, methods=["POST"]),
]
