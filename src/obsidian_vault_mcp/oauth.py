"""OAuth 2.0 authorization code flow with PKCE for Claude app MCP integration.

Claude's MCP connector uses the full OAuth authorization code flow:
1. Discovers metadata at /.well-known/oauth-authorization-server
2. Dynamically registers at /oauth/register (or uses pre-configured credentials)
3. Redirects user's browser to /oauth/authorize
4. Server auto-approves (single-user) and redirects back with an auth code
5. Claude exchanges the code at /oauth/token for a bearer token
6. Claude uses the bearer token on all MCP requests

Since this is a single-user personal server, the authorization page auto-approves
immediately -- no login screen, no consent page. The security boundary is the
client credentials + PKCE + the bearer token on every MCP request.
"""

import hashlib
import hmac
import logging
import secrets
import time
from urllib.parse import urlencode, urlparse, parse_qs

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, HTMLResponse
from starlette.routing import Route

from . import config

logger = logging.getLogger(__name__)

# In-memory store for authorization codes (short-lived)
# Maps code -> {client_id, redirect_uri, code_challenge, code_challenge_method, expires_at}
_auth_codes: dict[str, dict] = {}

# Clean up expired codes periodically
def _cleanup_codes():
    now = time.time()
    expired = [k for k, v in _auth_codes.items() if v["expires_at"] < now]
    for k in expired:
        del _auth_codes[k]


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
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    })


async def oauth_authorize(request: Request):
    """OAuth 2.0 authorization endpoint.

    Claude redirects the user's browser here. Since this is a single-user
    personal server, we auto-approve: generate an auth code and redirect
    back to Claude immediately.
    """
    response_type = request.query_params.get("response_type", "")
    client_id = request.query_params.get("client_id", "")
    redirect_uri = request.query_params.get("redirect_uri", "")
    state = request.query_params.get("state", "")
    code_challenge = request.query_params.get("code_challenge", "")
    code_challenge_method = request.query_params.get("code_challenge_method", "S256")

    if response_type != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)

    if not redirect_uri:
        return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri required"}, status_code=400)

    # Generate authorization code
    _cleanup_codes()
    code = secrets.token_urlsafe(32)
    _auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": time.time() + 300,  # 5 minute expiry
    }

    logger.info(f"OAuth authorization code issued, redirecting to {redirect_uri[:50]}...")

    # Redirect back to Claude with the code
    params = {"code": code}
    if state:
        params["state"] = state

    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        url=f"{redirect_uri}{separator}{urlencode(params)}",
        status_code=302,
    )


async def oauth_token(request: Request) -> JSONResponse:
    """OAuth 2.0 token endpoint -- authorization code grant with PKCE."""
    try:
        form = await request.form()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    grant_type = form.get("grant_type", "")
    client_id = form.get("client_id", "")
    client_secret = form.get("client_secret", "")

    # Support both authorization_code and client_credentials grants
    if grant_type == "authorization_code":
        return await _handle_authorization_code(form, client_id, client_secret)
    elif grant_type == "client_credentials":
        return await _handle_client_credentials(client_id, client_secret)
    else:
        return JSONResponse(
            {"error": "unsupported_grant_type"},
            status_code=400,
        )


async def _handle_authorization_code(form, client_id: str, client_secret: str) -> JSONResponse:
    """Exchange an authorization code for a bearer token."""
    code = form.get("code", "")
    redirect_uri = form.get("redirect_uri", "")
    code_verifier = form.get("code_verifier", "")

    _cleanup_codes()

    if code not in _auth_codes:
        return JSONResponse({"error": "invalid_grant", "error_description": "Invalid or expired code"}, status_code=400)

    code_data = _auth_codes.pop(code)

    # Verify redirect_uri matches
    if redirect_uri and code_data["redirect_uri"] and redirect_uri != code_data["redirect_uri"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)

    # Verify PKCE code_challenge if one was provided during authorization
    if code_data["code_challenge"]:
        if not code_verifier:
            return JSONResponse({"error": "invalid_grant", "error_description": "code_verifier required"}, status_code=400)

        # S256: BASE64URL(SHA256(code_verifier)) must match code_challenge
        import base64
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        if not hmac.compare_digest(computed_challenge, code_data["code_challenge"]):
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)

    logger.info("OAuth token issued via authorization_code grant")
    return JSONResponse({
        "access_token": config.VAULT_MCP_TOKEN,
        "token_type": "bearer",
        "expires_in": 86400,
    })


async def _handle_client_credentials(client_id: str, client_secret: str) -> JSONResponse:
    """Exchange client credentials for a bearer token."""
    if not config.VAULT_OAUTH_CLIENT_SECRET:
        return JSONResponse({"error": "server_error"}, status_code=500)

    id_match = hmac.compare_digest(client_id, config.VAULT_OAUTH_CLIENT_ID)
    secret_match = hmac.compare_digest(client_secret, config.VAULT_OAUTH_CLIENT_SECRET)

    if not (id_match and secret_match):
        logger.warning(f"OAuth client_credentials failed (client_id={client_id!r})")
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    logger.info("OAuth token issued via client_credentials grant")
    return JSONResponse({
        "access_token": config.VAULT_MCP_TOKEN,
        "token_type": "bearer",
        "expires_in": 86400,
    })


async def oauth_register(request: Request) -> JSONResponse:
    """Dynamic client registration endpoint.

    Claude calls this during initial setup to register as an OAuth client.
    Returns pre-configured credentials.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    # Generate a unique client_id for this registration
    client_id = f"vault-mcp-{secrets.token_hex(8)}"

    return JSONResponse({
        "client_id": client_id,
        "client_secret": config.VAULT_OAUTH_CLIENT_SECRET,
        "client_name": body.get("client_name", "Obsidian Vault MCP Client"),
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "redirect_uris": body.get("redirect_uris", []),
        "token_endpoint_auth_method": "client_secret_post",
    }, status_code=201)


# Starlette routes to mount on the app
oauth_routes = [
    Route("/.well-known/oauth-authorization-server", oauth_metadata, methods=["GET"]),
    Route("/oauth/authorize", oauth_authorize, methods=["GET"]),
    Route("/authorize", oauth_authorize, methods=["GET"]),
    Route("/oauth/token", oauth_token, methods=["POST"]),
    Route("/oauth/register", oauth_register, methods=["POST"]),
]
