"""OAuth 2.0 authorization-code flow with PKCE + an interactive login gate.

The Claude / ChatGPT MCP connectors drive this flow automatically:
1. Discover metadata at /.well-known/oauth-authorization-server
2. Dynamically register at /oauth/register (gets a client_id + a per-client secret)
3. Open the user's browser at /oauth/authorize
4. >>> The user logs in (username + password) -- THEN an authorization code is issued <<<
5. The client exchanges the code at /oauth/token (PKCE verified) for a bearer token
6. The client sends the bearer token on every MCP request

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

Remaining hardening tracked separately (see the fix write-up): the issued bearer
token is still the single static VAULT_MCP_TOKEN. Replacing it with per-client,
expiring, revocable tokens is a follow-up.
"""

import base64
import hashlib
import hmac
import html
import logging
import secrets
import time
from urllib.parse import urlencode, urlparse

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, HTMLResponse
from starlette.routing import Route

from . import config

logger = logging.getLogger(__name__)

# In-memory store for authorization codes (short-lived).
# Maps code -> {client_id, redirect_uri, code_challenge, code_challenge_method, expires_at}
_auth_codes: dict[str, dict] = {}

# In-memory store for dynamically registered clients.
# Maps client_id -> {client_secret, redirect_uris: [...], created_at}
_clients: dict[str, dict] = {}


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
    record = _clients.get(client_id)
    if record is not None:
        # DCR-registered client: exact-match its registered URIs (empty list -> deny).
        return redirect_uri in (record.get("redirect_uris") or [])
    if client_id == config.VAULT_OAUTH_CLIENT_ID:
        # Operator-configured client: only the explicit allowlist is accepted.
        return redirect_uri in config.VAULT_OAUTH_REDIRECT_URIS
    return False


def _client_known(client_id: str) -> bool:
    return client_id in _clients or (
        bool(config.VAULT_OAUTH_CLIENT_ID) and client_id == config.VAULT_OAUTH_CLIENT_ID
    )


def _issue_code_redirect(client_id: str, redirect_uri: str, state: str,
                         code_challenge: str, code_challenge_method: str):
    """Mint an authorization code and 302 back to the client."""
    _cleanup_codes()
    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": time.time() + 300,  # 5 minute expiry
    }
    logger.info("OAuth authorization code issued after successful login.")
    params = {"code": code}
    if state:
        params["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(url=f"{redirect_uri}{separator}{urlencode(params)}", status_code=302)


def _login_form(params: dict, error: str = "") -> HTMLResponse:
    """Render the login page, carrying the OAuth params as hidden fields.

    Every reflected value is HTML-escaped to avoid reflected XSS.
    """
    hidden = "\n".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
        for k, v in params.items() if v
    )
    err_html = f'<p class="err">{html.escape(error)}</p>' if error else ""
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
    return HTMLResponse(page, status_code=status)


def _misconfigured_page() -> HTMLResponse:
    return HTMLResponse(
        "<h1>Server not configured for login</h1>"
        "<p>This server requires <code>VAULT_OAUTH_PASSWORD</code> to be set before it can "
        "authorize access to your vault. Set it and restart.</p>",
        status_code=503,
    )


async def oauth_metadata(request: Request) -> JSONResponse:
    """RFC 8414 OAuth authorization server metadata."""
    base_url = str(request.base_url).rstrip("/")
    return JSONResponse({
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/oauth/register",
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
    })


async def oauth_protected_resource(request: Request) -> JSONResponse:
    """RFC 9728 OAuth protected-resource metadata. Claude/ChatGPT request this path
    during discovery; it must be reachable without a bearer token (#20). With the MCP
    endpoint served at "/" (#19), the protected resource is the base URL itself."""
    base_url = str(request.base_url).rstrip("/")
    return JSONResponse({
        "resource": base_url,
        "authorization_servers": [base_url],
        "bearer_methods_supported": ["header"],
    })


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

    oauth_params = {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
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

    # POST: verify the submitted credentials.
    if not _check_credentials(form.get("username", ""), form.get("password", "")):
        logger.warning("OAuth login failed.")
        return _login_form(oauth_params, error="Incorrect username or password.")

    return _issue_code_redirect(client_id, redirect_uri, state, code_challenge, code_challenge_method)


async def oauth_token(request: Request) -> JSONResponse:
    """OAuth 2.0 token endpoint -- authorization code grant with PKCE."""
    try:
        form = await request.form()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    grant_type = form.get("grant_type", "")
    client_id = form.get("client_id", "")
    client_secret = form.get("client_secret", "")

    if grant_type == "authorization_code":
        return await _handle_authorization_code(form)
    elif grant_type == "client_credentials":
        return await _handle_client_credentials(client_id, client_secret)
    else:
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


async def _handle_authorization_code(form) -> JSONResponse:
    """Exchange an authorization code for a bearer token. PKCE + redirect_uri are
    both mandatory (no optional-verification escape hatches)."""
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

    logger.info("OAuth token issued via authorization_code grant.")
    return JSONResponse({
        "access_token": config.VAULT_MCP_TOKEN,
        "token_type": "bearer",
        "expires_in": 86400,
    })


async def _handle_client_credentials(client_id: str, client_secret: str) -> JSONResponse:
    """Headless grant for an operator-configured client (machine-to-machine).

    Validated against the configured VAULT_OAUTH_CLIENT_ID/SECRET. Note: /oauth/register
    no longer hands these out, so this path requires the operator's real secret.
    """
    if not config.VAULT_OAUTH_CLIENT_SECRET:
        return JSONResponse({"error": "server_error"}, status_code=500)

    id_match = hmac.compare_digest(client_id, config.VAULT_OAUTH_CLIENT_ID)
    secret_match = hmac.compare_digest(client_secret, config.VAULT_OAUTH_CLIENT_SECRET)
    if not (id_match and secret_match):
        logger.warning("OAuth client_credentials failed.")
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    logger.info("OAuth token issued via client_credentials grant.")
    return JSONResponse({
        "access_token": config.VAULT_MCP_TOKEN,
        "token_type": "bearer",
        "expires_in": 86400,
    })


async def oauth_register(request: Request) -> JSONResponse:
    """Dynamic client registration (RFC 7591).

    Non-authorizing: stores a client record and returns a freshly generated
    per-client secret. NEVER returns the server's configured secret or the vault
    bearer token. Registering a client confers no access on its own -- the human
    must still log in at /oauth/authorize.
    """
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
        parsed = urlparse(uri)
        is_loopback = parsed.scheme == "http" and (parsed.hostname in {"127.0.0.1", "localhost", "::1"})
        if parsed.scheme == "https" or is_loopback:
            redirect_uris.append(uri)

    client_id = f"vault-mcp-{secrets.token_hex(8)}"
    client_secret = secrets.token_hex(32)  # per-client, NOT config.VAULT_OAUTH_CLIENT_SECRET
    _clients[client_id] = {
        "client_secret": client_secret,
        "redirect_uris": redirect_uris,
        "created_at": time.time(),
    }

    return JSONResponse({
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": body.get("client_name", "Obsidian Vault MCP Client"),
        "grant_types": ["authorization_code"],
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
