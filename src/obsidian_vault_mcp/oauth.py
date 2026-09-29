"""OAuth 2.0 authorization-code flow with PKCE + an interactive login gate.

The Claude / ChatGPT MCP connectors drive this flow automatically:
1. Discover metadata at /.well-known/oauth-authorization-server
2. Dynamically register at /oauth/register (gets a client_id + a per-client secret)
3. Open the user's browser at /oauth/authorize
4. >>> The user logs in (username + password) -- THEN an authorization code is issued <<<
5. The client exchanges the code at /oauth/token (PKCE verified) for its own access
   and refresh token
6. The client sends the access token on every MCP request

Security model (fix for issues #8 / #29)
----------------------------------------
The previous version auto-approved every /oauth/authorize request with no user
check, so anyone who could reach the URL could obtain the vault bearer token.
This version closes that hole:

- /oauth/authorize authenticates the human (login form) before issuing any code.
  It NEVER auto-approves anonymous requests; with no VAULT_OAUTH_PASSWORD set it
  fails closed (503). The password is required on every authorization, so there is
  no ambient session for a cross-site request (or a self-registered attacker
  client) to ride on.
- /oauth/register is non-authorizing: it stores a client record and returns a
  freshly generated per-client secret. It NEVER echoes the server's configured
  secret or the vault bearer token.
- redirect_uri must be https (or loopback http) and -- for a dynamically
  registered client -- must exactly match a registered URI, at both authorize and
  token time. This prevents open-redirect / code-exfiltration.
- PKCE S256 is mandatory on the authorization-code grant.
- The authorization-code grant issues per-client, expiring, revocable tokens kept in
  the store (oauth_state.py), never the static VAULT_MCP_TOKEN.
"""

import base64
import hashlib
import hmac
import html
import logging
import math
import secrets
import threading
import time
from collections import deque
from pathlib import Path
from urllib.parse import urlencode, urlparse, urlsplit, urlunsplit

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, HTMLResponse
from starlette.routing import Route

from . import config
from .oauth_state import InvalidClient, InvalidGrant, InvalidTarget, IssuedToken, OAuthState

logger = logging.getLogger(__name__)

# In-memory store for authorization codes (short-lived).
# Maps code -> {client_id, redirect_uri, code_challenge, code_challenge_method, resource,
# expires_at}
_auth_codes: dict[str, dict] = {}

# Registered clients live in the SQLite store (oauth_state.py), beside the legacy JSON
# registry at config.OAUTH_CLIENTS_PATH, which the store imports on every open. A
# registry kept only in memory is wiped on every restart, which breaks already-connected
# MCP clients: they replay a client_id the restarted server no longer recognizes, so
# /oauth/authorize rejects it with "Invalid or unregistered redirect_uri" and the only
# recourse is removing and re-adding the connector. Importing this module opens nothing;
# the store opens on first use.
_state: OAuthState | None = None
_state_lock = threading.Lock()


def _state_path() -> Path:
    """The store file, beside the legacy registry it imports."""
    return config.OAUTH_CLIENTS_PATH.with_name("oauth_state.sqlite3")


def get_oauth_state() -> OAuthState:
    """The open store, opened on first use."""
    global _state
    with _state_lock:
        if _state is None:
            _state = OAuthState(_state_path(), legacy_path=config.OAUTH_CLIENTS_PATH)
        return _state


def close_oauth_state() -> None:
    """Close the store; the next use opens it again."""
    global _state
    with _state_lock:
        if _state is not None:
            _state.close()
            _state = None


# --- Brakes on the two unauthenticated write paths (#97) ---------------------------------
#
# Failed password attempts at /oauth/authorize and registrations at /oauth/register are
# counted globally, not per address: someone guessing passwords can switch addresses,
# and one correct guess hands over the whole vault. The numbers are far above what the
# owner does and far below what guessing needs. The trade-off: someone hammering the
# login can hold it closed for the owner until the window passes; tokens already issued
# keep working, so connected clients are not affected.
LOGIN_FAILURE_LIMIT = 10
LOGIN_FAILURE_WINDOW_SECONDS = 15 * 60
REGISTRATION_LIMIT = 20
REGISTRATION_WINDOW_SECONDS = 60 * 60

_clock = time.monotonic  # tests move time through this


class _SlidingLimit:
    """At most ``limit`` events in any ``window`` seconds, across all callers."""

    def __init__(self, limit: int, window: float):
        self.limit = limit
        self.window = window
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        while self._events and self._events[0] <= now - self.window:
            self._events.popleft()

    def retry_after(self) -> int:
        """Seconds until the next event is allowed; 0 when it is allowed now."""
        with self._lock:
            now = _clock()
            self._prune(now)
            if len(self._events) < self.limit:
                return 0
            return max(1, math.ceil(self._events[0] + self.window - now))

    def record(self) -> None:
        with self._lock:
            now = _clock()
            self._prune(now)
            self._events.append(now)


_login_failures = _SlidingLimit(LOGIN_FAILURE_LIMIT, LOGIN_FAILURE_WINDOW_SECONDS)
_registrations = _SlidingLimit(REGISTRATION_LIMIT, REGISTRATION_WINDOW_SECONDS)


def _cleanup_codes():
    now = time.time()
    expired = [k for k, v in _auth_codes.items() if v["expires_at"] < now]
    for k in expired:
        del _auth_codes[k]


def _login_configured() -> bool:
    """True if an interactive login credential is configured."""
    return bool(config.VAULT_OAUTH_PASSWORD)


def _check_credentials(username: str, password: str) -> bool:
    """Constant-time check of the submitted login credentials."""
    if not config.VAULT_OAUTH_PASSWORD:
        return False
    user_ok = hmac.compare_digest(username or "", config.VAULT_OAUTH_USERNAME)
    pass_ok = hmac.compare_digest(password or "", config.VAULT_OAUTH_PASSWORD)
    return user_ok and pass_ok


def _redirect_uri_ok(client_id: str, redirect_uri: str) -> bool:
    """Validate redirect_uri: must be https (or loopback http) AND exact-match an
    allowlist for the client -- no open fallthrough (#4):
      - DCR-registered client  -> must match one of its registered redirect_uris.
      - operator-configured client -> must match VAULT_OAUTH_REDIRECT_URIS.
    A client with no allowlisted URIs cannot use the browser authorization-code flow.
    """
    if not redirect_uri:
        return False
    parsed = urlparse(redirect_uri)
    is_loopback = parsed.scheme == "http" and (parsed.hostname in {"127.0.0.1", "localhost", "::1"})
    if parsed.scheme != "https" and not is_loopback:
        return False
    if client_id == config.VAULT_OAUTH_CLIENT_ID:
        # Operator-configured client: only the explicit allowlist is accepted. It is
        # checked before the store, whose row for this client is written at token time
        # and would miss a later change to the allowlist.
        return redirect_uri in config.VAULT_OAUTH_REDIRECT_URIS
    # DCR-registered client: exact-match its registered URIs (none -> deny). A revoked
    # or unknown client matches none.
    return get_oauth_state().client_redirect_uri_allowed(client_id, redirect_uri)


def _client_known(client_id: str) -> bool:
    """A registered client that is not revoked, or the one the operator configured."""
    client = get_oauth_state().get_client(client_id)
    if client is not None:
        return client.revoked_at is None
    return bool(config.VAULT_OAUTH_CLIENT_ID) and client_id == config.VAULT_OAUTH_CLIENT_ID


def _issue_code_redirect(client_id: str, redirect_uri: str, state: str,
                         code_challenge: str, code_challenge_method: str, resource: str):
    """Mint an authorization code and 302 back to the client."""
    _cleanup_codes()
    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "resource": resource,
        "expires_at": time.time() + 300,  # 5 minute expiry
    }
    logger.info("OAuth authorization code issued after successful login.")
    params = {"code": code}
    if state:
        params["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(url=f"{redirect_uri}{separator}{urlencode(params)}", status_code=302)


def _login_form(params: dict, error: str = "", status: int | None = None, headers: dict | None = None) -> HTMLResponse:
    """Render the login page, carrying the OAuth params as hidden fields.

    Every reflected value is HTML-escaped to avoid reflected XSS.
    """
    hidden = "\n".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
        for k, v in params.items() if v
    )
    err_html = f'<p class="err">{html.escape(error)}</p>' if error else ""
    if status is None:
        status = 401 if error else 200
    page = f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize Obsidian Vault access</title>
<style>
 body{{font-family:-apple-system,system-ui,sans-serif;background:#1e1e2e;color:#cdd6f4;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}}
 form{{background:#313244;padding:2rem;border-radius:12px;width:300px;box-shadow:0 8px 24px rgba(0,0,0,.4)}}
 h1{{font-size:1.1rem;margin:0 0 1rem}}
 label{{display:block;font-size:.8rem;margin:.6rem 0 .2rem;color:#a6adc8}}
 input[type=text],input[type=password]{{width:100%;box-sizing:border-box;padding:.5rem;border-radius:6px;border:1px solid #45475a;background:#1e1e2e;color:#cdd6f4}}
 button{{margin-top:1rem;width:100%;padding:.6rem;border:0;border-radius:6px;background:#89b4fa;color:#1e1e2e;font-weight:600;cursor:pointer}}
 .err{{color:#f38ba8;font-size:.8rem;margin:.4rem 0 0}}
 .sub{{font-size:.75rem;color:#6c7086;margin-top:1rem}}
</style></head>
<body>
 <form method="post" action="/oauth/authorize">
  <h1>🔒 Authorize access to your vault</h1>
  {hidden}
  <label for="u">Username</label>
  <input id="u" type="text" name="username" autocomplete="username" autofocus>
  <label for="p">Password</label>
  <input id="p" type="password" name="password" autocomplete="current-password">
  {err_html}
  <button type="submit">Authorize</button>
  <p class="sub">A client is requesting access to your Obsidian vault.</p>
 </form>
</body></html>"""
    return HTMLResponse(page, status_code=status, headers=headers)


def _misconfigured_page() -> HTMLResponse:
    return HTMLResponse(
        "<h1>Server not configured for login</h1>"
        "<p>This server requires <code>VAULT_OAUTH_PASSWORD</code> to be set before it can "
        "authorize access to your vault. Set it and restart.</p>",
        status_code=503,
    )


async def oauth_metadata(request: Request) -> JSONResponse:
    """RFC 8414 OAuth authorization server metadata."""
    base_url = config.advertised_base_url(str(request.base_url))
    return JSONResponse({
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/oauth/register",
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
    })


async def oauth_protected_resource(request: Request) -> JSONResponse:
    """RFC 9728 OAuth protected-resource metadata. Claude/ChatGPT request this path
    during discovery; it must be reachable without a bearer token (#20).

    The ``resource`` identifier must be the actual MCP endpoint URL (RFC 9728 / RFC
    8707), i.e. the base URL plus VAULT_MCP_PATH. When the endpoint is at "/" (#19)
    that collapses to the base URL; when mounted under a subpath (VAULT_MCP_PATH,
    e.g. "/mcp" — added in #43) it must include that path. Strict clients such as
    Home Assistant's MCP integration reject the metadata unless ``resource`` exactly
    equals the endpoint they connected to; lenient clients (claude.ai) ignore the
    mismatch, which is why the "/"-only assumption went unnoticed."""
    return JSONResponse({
        "resource": canonical_resource(request),
        "authorization_servers": [config.advertised_base_url(str(request.base_url))],
        "bearer_methods_supported": ["header"],
    })


def canonical_resource(request: Request) -> str:
    """The RFC 8707 resource of this server: its MCP endpoint URL."""
    base_url = config.advertised_base_url(str(request.base_url))
    path = config.VAULT_MCP_PATH
    return base_url if path == "/" else f"{base_url}{path}"


def _normalize_resource(uri: str) -> str:
    """The resource URI in one form: scheme and host lowercased, one trailing slash of
    the path removed. An empty path and "/" come out the same, as RFC 3986 treats them."""
    parts = urlsplit(uri)
    path = parts.path[:-1] if parts.path.endswith("/") else parts.path
    return urlunsplit(parts._replace(
        scheme=parts.scheme.lower(), netloc=parts.netloc.lower(), path=path,
    ))


def resource_matches(provided: str, canonical: str) -> bool:
    """Whether an RFC 8707 resource names the MCP endpoint of this server.

    The MCP SDK sends "https://host/" for an advertised "https://host", so the two
    are compared after normalization. Each side is normalized exactly once: a second
    pass would strip another slash and accept "https://host//", a different URI.
    """
    return _normalize_resource(provided) == _normalize_resource(canonical)


async def oauth_authorize(request: Request):
    """OAuth 2.0 authorization endpoint with an interactive login gate.

    GET  -> validate the request, then render a login form (or auto-approve only
            under the explicit localhost escape hatch).
    POST -> verify submitted credentials, then issue an authorization code.
    """
    if request.method == "POST":
        form = await request.form()
        getp = form.get
    else:
        getp = request.query_params.get

    response_type = getp("response_type", "") or ""
    client_id = getp("client_id", "") or ""
    redirect_uri = getp("redirect_uri", "") or ""
    state = getp("state", "") or ""
    code_challenge = getp("code_challenge", "") or ""
    code_challenge_method = getp("code_challenge_method", "S256") or "S256"
    resource = getp("resource", "") or ""

    # --- Validate the OAuth request shape (independent of authentication) ---
    if response_type != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
    if not client_id or not _client_known(client_id):
        return JSONResponse(
            {"error": "invalid_client", "error_description": "Unknown client; register via /oauth/register first."},
            status_code=400,
        )
    if not _redirect_uri_ok(client_id, redirect_uri):
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Invalid or unregistered redirect_uri."},
            status_code=400,
        )
    if not code_challenge or code_challenge_method != "S256":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "PKCE S256 (code_challenge) is required."},
            status_code=400,
        )
    # RFC 8707: the resource is optional; one that is sent must name this server.
    canonical = canonical_resource(request)
    if resource and not resource_matches(resource, canonical):
        return JSONResponse(
            {"error": "invalid_target", "error_description": "resource must be the MCP endpoint of this server."},
            status_code=400,
        )

    oauth_params = {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "resource": resource,
    }

    # --- Authentication gate ---
    # Fail CLOSED: with no login credential configured there is no safe way to
    # authenticate the human, so we refuse to issue codes. There is deliberately
    # no "auto-approve" escape hatch — an unauthenticated authorize endpoint is
    # exactly the vulnerability this fix closes (issues #8 / #29).
    if not _login_configured():
        logger.error("Refusing to authorize: VAULT_OAUTH_PASSWORD is not set.")
        return _misconfigured_page()

    if request.method != "POST":
        # No credentials yet -- show the login form.
        return _login_form(oauth_params)

    # POST: refuse every attempt while the failure brake is tripped, the correct password
    # included; otherwise the brake would only slow a guesser down, not stop a lucky guess.
    wait = _login_failures.retry_after()
    if wait:
        logger.warning("OAuth login refused: too many failed attempts, %ss until the next try.", wait)
        return _login_form(
            oauth_params,
            error=f"Too many failed sign-in attempts. Try again in {max(1, wait // 60)} minute(s).",
            status=429,
            headers={"Retry-After": str(wait)},
        )

    # Verify the submitted credentials.
    if not _check_credentials(form.get("username", ""), form.get("password", "")):
        _login_failures.record()
        logger.warning("OAuth login failed.")
        return _login_form(oauth_params, error="Incorrect username or password.")

    # The code carries the resource of this authorization; the token request may reach
    # the server under another Host.
    return _issue_code_redirect(client_id, redirect_uri, state, code_challenge, code_challenge_method,
                                canonical)


async def oauth_token(request: Request) -> JSONResponse:
    """OAuth 2.0 token endpoint: authorization code grant with PKCE, refresh, and
    client credentials for the operator client."""
    try:
        form = await request.form()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    grant_type = form.get("grant_type", "")
    client_id = form.get("client_id", "")
    client_secret = form.get("client_secret", "")

    if grant_type == "authorization_code":
        return await _handle_authorization_code(form)
    elif grant_type == "refresh_token":
        return await _handle_refresh_token(form)
    elif grant_type == "client_credentials":
        return await _handle_client_credentials(
            client_id, client_secret, form.get("resource", ""), canonical_resource(request)
        )
    else:
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


def _client_secret_ok(client_id: str, client_secret: str) -> bool:
    """Check a sent secret: the operator client against the configured one, a
    registered client against the store."""
    if client_id == config.VAULT_OAUTH_CLIENT_ID:
        # Compared as bytes: hmac.compare_digest raises on str that is not ASCII.
        return bool(config.VAULT_OAUTH_CLIENT_SECRET) and hmac.compare_digest(
            client_secret.encode(), config.VAULT_OAUTH_CLIENT_SECRET.encode()
        )
    return get_oauth_state().verify_client_secret(client_id, client_secret)


def _operator_client_state() -> OAuthState:
    """The store, holding a row for the operator client.

    The operator client has no row until its first token; its secret and redirects stay
    in the configuration, the row carries its tokens and revocation.
    """
    state = get_oauth_state()
    state.ensure_static_client(config.VAULT_OAUTH_CLIENT_ID)
    return state


def _token_response(issued: IssuedToken) -> JSONResponse:
    """The token endpoint answer for tokens from the store."""
    payload = {
        "access_token": issued.access_token,
        "token_type": "bearer",
        "expires_in": int(issued.token.expires_at - issued.token.issued_at),
    }
    if issued.refresh_token is not None:
        payload["refresh_token"] = issued.refresh_token
    return JSONResponse(payload)


async def _handle_authorization_code(form) -> JSONResponse:
    """Exchange an authorization code for an access and refresh token of that client.
    PKCE + redirect_uri are both mandatory (no optional-verification escape hatches);
    a client secret is optional, as for a public client, but one that is sent must be
    right."""
    code = form.get("code", "")
    redirect_uri = form.get("redirect_uri", "")
    code_verifier = form.get("code_verifier", "")

    _cleanup_codes()

    if not code or code not in _auth_codes:
        return JSONResponse({"error": "invalid_grant", "error_description": "Invalid or expired code"}, status_code=400)

    code_data = _auth_codes.pop(code)  # single-use

    # RFC 6749 4.1.3: the code must be redeemed by the client it was issued to (#4).
    request_client_id = form.get("client_id", "")
    if not hmac.compare_digest(request_client_id or "", code_data.get("client_id") or ""):
        return JSONResponse({"error": "invalid_grant", "error_description": "client_id mismatch"}, status_code=400)
    client_id = code_data["client_id"]

    client_secret = form.get("client_secret", "")
    if client_secret and not _client_secret_ok(client_id, client_secret):
        logger.warning("OAuth authorization_code refused: wrong client secret.")
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    # RFC 8707: the resource is optional here too; one that is sent must name the
    # resource the code was issued for.
    resource = form.get("resource", "")
    if resource and not resource_matches(resource, code_data["resource"]):
        return JSONResponse(
            {"error": "invalid_target", "error_description": "resource does not match the authorization"},
            status_code=400,
        )

    # redirect_uri must be present and match what was bound to the code.
    if not redirect_uri or redirect_uri != code_data["redirect_uri"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)

    # PKCE is mandatory: a challenge was required at /authorize, so a verifier is required here.
    if not code_data.get("code_challenge"):
        return JSONResponse({"error": "invalid_grant", "error_description": "missing PKCE challenge"}, status_code=400)
    if not code_verifier:
        return JSONResponse({"error": "invalid_grant", "error_description": "code_verifier required"}, status_code=400)

    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(computed_challenge, code_data["code_challenge"]):
        return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)

    state = _operator_client_state() if client_id == config.VAULT_OAUTH_CLIENT_ID else get_oauth_state()
    try:
        # Refuses a client revoked since the code was issued.
        issued = state.issue_token_pair(client_id=client_id, resource=code_data["resource"])
    except InvalidClient:
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    logger.info("OAuth token issued via authorization_code grant.")
    return _token_response(issued)


async def _handle_refresh_token(form) -> JSONResponse:
    """Spend a refresh token for the next pair. As on the code grant, a client secret is
    optional, but one that is sent must be right."""
    refresh_token = form.get("refresh_token", "")
    client_id = form.get("client_id", "")
    if not refresh_token or not client_id:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "refresh_token and client_id are required"},
            status_code=400,
        )

    client_secret = form.get("client_secret", "")
    if client_secret and not _client_secret_ok(client_id, client_secret):
        logger.warning("OAuth refresh_token refused: wrong client secret.")
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    # RFC 8707: the resource is optional; one that is sent must name the resource the
    # refresh token was issued for.
    resource = form.get("resource", "")
    try:
        issued = get_oauth_state().redeem_refresh_token(
            refresh_token=refresh_token,
            client_id=client_id,
            resource_ok=lambda stored: not resource or resource_matches(resource, stored),
        )
    except InvalidClient:
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    except InvalidTarget:
        return JSONResponse(
            {"error": "invalid_target", "error_description": "resource does not match the authorization"},
            status_code=400,
        )
    except InvalidGrant:
        return JSONResponse({"error": "invalid_grant", "error_description": "Invalid refresh token"}, status_code=400)

    logger.info("OAuth token issued via refresh_token grant.")
    return _token_response(issued)


async def _handle_client_credentials(client_id: str, client_secret: str, resource: str,
                                     canonical: str) -> JSONResponse:
    """Headless grant for an operator-configured client (machine-to-machine).

    Validated against the configured VAULT_OAUTH_CLIENT_ID/SECRET. Note: /oauth/register
    no longer hands these out, so this path requires the operator's real secret. The
    access token comes alone: the client can ask again with its secret.
    """
    if not config.VAULT_OAUTH_CLIENT_SECRET:
        return JSONResponse({"error": "server_error"}, status_code=500)

    # Compared as bytes: hmac.compare_digest raises on str that is not ASCII.
    id_match = hmac.compare_digest(client_id.encode(), config.VAULT_OAUTH_CLIENT_ID.encode())
    if not (id_match and _client_secret_ok(config.VAULT_OAUTH_CLIENT_ID, client_secret)):
        logger.warning("OAuth client_credentials failed.")
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    # RFC 8707: the resource is optional; one that is sent must name this server.
    if resource and not resource_matches(resource, canonical):
        return JSONResponse(
            {"error": "invalid_target", "error_description": "resource must be the MCP endpoint of this server."},
            status_code=400,
        )

    try:
        issued = _operator_client_state().issue_access_token(
            client_id=config.VAULT_OAUTH_CLIENT_ID, resource=canonical
        )
    except InvalidClient:
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    logger.info("OAuth token issued via client_credentials grant.")
    return _token_response(issued)


async def oauth_register(request: Request) -> JSONResponse:
    """Dynamic client registration (RFC 7591).

    Non-authorizing: stores a client record and returns a freshly generated
    per-client secret. NEVER returns the server's configured secret or the vault
    bearer token. Registering a client confers no access on its own -- the human
    must still log in at /oauth/authorize.
    """
    wait = _registrations.retry_after()
    if wait:
        logger.warning("OAuth registration refused: registration limit reached, %ss until the next.", wait)
        return JSONResponse(
            {"error": "too_many_requests",
             "error_description": "Too many client registrations; try again later."},
            status_code=429,
            headers={"Retry-After": str(wait)},
        )

    try:
        body = await request.json()
    except Exception:
        body = {}

    # Only accept valid https / loopback redirect URIs.
    requested = body.get("redirect_uris", []) or []
    redirect_uris = []
    for uri in requested:
        if not isinstance(uri, str):
            continue
        try:
            uri.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate survives JSON parsing but not the store: drop it like any
            # other unusable URI rather than fail the registration.
            continue
        parsed = urlparse(uri)
        is_loopback = parsed.scheme == "http" and (parsed.hostname in {"127.0.0.1", "localhost", "::1"})
        if parsed.scheme == "https" or is_loopback:
            redirect_uris.append(uri)

    # The store keeps only a hash of the per-client secret, NOT config.VAULT_OAUTH_CLIENT_SECRET.
    registered = get_oauth_state().register_client(redirect_uris)
    client_id, client_secret = registered.client.client_id, registered.client_secret
    _registrations.record()

    return JSONResponse({
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": body.get("client_name", "Obsidian Vault MCP Client"),
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "client_secret_post",
    }, status_code=201)


# Starlette routes to mount on the app
oauth_routes = [
    Route("/.well-known/oauth-authorization-server", oauth_metadata, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]),
    Route("/oauth/authorize", oauth_authorize, methods=["GET", "POST"]),
    Route("/oauth/token", oauth_token, methods=["POST"]),
    Route("/oauth/register", oauth_register, methods=["POST"]),
]
