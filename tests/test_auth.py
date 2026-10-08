"""Tests for the bearer-auth middleware's RFC 9728 WWW-Authenticate challenge."""

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth as auth_module


@pytest.fixture
def client(monkeypatch):
    # Bind a known token into the middleware's module namespace.
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")

    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", ok)])
    app.add_middleware(auth_module.BearerAuthMiddleware)
    return TestClient(app)


def test_missing_auth_returns_401_with_challenge(client):
    r = client.get("/")
    assert r.status_code == 401
    wa = r.headers.get("WWW-Authenticate", "")
    assert wa.startswith("Bearer ")
    assert "/.well-known/oauth-protected-resource" in wa
    assert 'resource_metadata="' in wa
    assert 'error="invalid_request"' in wa


def test_bad_token_returns_401_with_invalid_token_challenge(client):
    r = client.get("/", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401
    wa = r.headers.get("WWW-Authenticate", "")
    assert 'error="invalid_token"' in wa
    assert "/.well-known/oauth-protected-resource" in wa


def test_valid_token_passes_through(client):
    r = client.get("/", headers={"Authorization": "Bearer secret-token"})
    assert r.status_code == 200
    assert r.text == "ok"
    assert "WWW-Authenticate" not in r.headers


def test_token_that_is_not_ascii_is_refused(client):
    # Sent as bytes: the server decodes the header as latin-1, and comparing such text as
    # str raises instead of answering.
    r = client.get("/", headers={"Authorization": b"Bearer t\xe9st"})

    assert r.status_code == 401
    assert 'error="invalid_token"' in r.headers["WWW-Authenticate"]


# --- Per-client OAuth tokens -------------------------------------------------------------

from obsidian_vault_mcp import config, oauth  # noqa: E402
from obsidian_vault_mcp.context import current_request_context  # noqa: E402

ROOT = "https://obsidian.example.xyz"


@pytest.fixture
def v1_client(monkeypatch):
    """The middleware in front of an MCP endpoint at ROOT/mcp that reports the audit client."""
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")
    monkeypatch.setattr(config, "VAULT_MCP_PUBLIC_URL", ROOT)
    monkeypatch.setattr(config, "VAULT_MCP_PATH", "/mcp")

    async def whoami(request):
        return PlainTextResponse(current_request_context().get("client") or "")

    app = Starlette(routes=[Route("/mcp", whoami)])
    app.add_middleware(auth_module.BearerAuthMiddleware)
    return TestClient(app)


def _v1_token(resource):
    """A registered client and an access token issued to it for the given resource."""
    state = oauth.get_oauth_state()
    client_id = state.register_client(["https://app.example/cb"]).client.client_id
    return client_id, state.issue_token_pair(client_id=client_id, resource=resource).access_token


def _call(v1_client, token):
    """Call the MCP endpoint with a bearer token."""
    return v1_client.get("/mcp", headers={"Authorization": f"Bearer {token}"})


def test_v1_token_passes_and_names_its_client(v1_client):
    client_id, token = _v1_token(f"{ROOT}/mcp")

    r = _call(v1_client, token)

    assert r.status_code == 200
    assert r.text == client_id


@pytest.mark.parametrize(
    "stored", [f"{ROOT}/mcp/", f"{ROOT.upper()}/mcp"], ids=["trailing-slash", "shouted-host"]
)
def test_v1_token_accepts_other_spellings_of_the_resource(v1_client, stored):
    _client_id, token = _v1_token(stored)

    assert _call(v1_client, token).status_code == 200


# --- The exemption check reads the decoded ASGI path, not request.url.path ---------------
#
# request.url.path is parsed back out of a URL string, so an encoded "?" or "#" in the
# path (%3F, %23) truncates it: "/health%3F/x" reads as "/health" to the middleware while
# the router matches the decoded "/health?/x". These go through build_app() so the real
# middleware stack and exempt set are what is tested.

from obsidian_vault_mcp import server  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402


@pytest.fixture
def real_app_client(vault_dir, monkeypatch):
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")
    return TestClient(server.build_app(), raise_server_exceptions=False)


@pytest.mark.parametrize("path", ["/health%3F/x", "/health%23/x", "/oauth/token%3F/x"])
def test_encoded_delimiter_does_not_borrow_an_exemption(real_app_client, path):
    assert real_app_client.get(path).status_code == 401
    assert real_app_client.post(path).status_code == 401


def test_route_behind_an_encoded_delimiter_still_needs_the_token(vault_dir, monkeypatch):
    """The consequence, not just the status code: a handler must not run tokenless."""
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")
    served = []

    class Ext:
        def register_routes(self, app):
            async def handler(request):
                served.append(request.scope["path"])
                return JSONResponse({"ok": True})

            app.routes.insert(0, Route("/health?/x", handler, methods=["GET"]))

    c = TestClient(server.build_app([Ext()]), raise_server_exceptions=False)

    assert c.get("/health%3F/x").status_code == 401
    assert served == []
    assert c.get("/health%3F/x", headers={"Authorization": "Bearer secret-token"}).status_code == 200


def test_exempt_paths_stay_exempt_with_a_real_query_string(real_app_client):
    assert real_app_client.get("/health").status_code == 200
    assert real_app_client.get("/health?probe=1").status_code == 200


# --- A per-client token end to end through build_app() -----------------------------------

import base64  # noqa: E402
import hashlib  # noqa: E402
import time  # noqa: E402
from io import StringIO  # noqa: E402

from obsidian_vault_mcp import oauth_admin, oauth_state  # noqa: E402

LOOPBACK = "http://127.0.0.1:8420"
REDIRECT = "https://app.example/cb"


def _oauth_v1_token(app_client):
    """Register, sign in and redeem a code through the served OAuth routes."""
    registered = app_client.post("/oauth/register", json={"redirect_uris": [REDIRECT]})
    client_id = registered.json()["client_id"]
    verifier = "verifier-abc123_this-is-long-enough-for-pkce-xyz"
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    signed_in = app_client.post("/oauth/authorize", follow_redirects=False, data={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
        "code_challenge": challenge, "code_challenge_method": "S256",
        "username": "obsidian", "password": "hunter2",
    })
    code = signed_in.headers["location"].split("code=")[1].split("&")[0]
    issued = app_client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": REDIRECT, "code_verifier": verifier,
    })
    return issued.json()["access_token"]


def _tool_call(app_client, name, arguments, token=None):
    """One MCP tools/call over the served transport."""
    headers = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return app_client.post("/", headers=headers, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })


def test_oauth_v1_token_writes_and_reads_through_mcp(vault_dir, monkeypatch):
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")
    monkeypatch.setattr(config, "VAULT_OAUTH_USERNAME", "obsidian")
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    monkeypatch.setattr(config, "VAULT_MCP_PUBLIC_URL", "")
    # A startable session manager per test, as in the Cloudflare Access app tests.
    monkeypatch.setattr(server.mcp, "_session_manager", None)
    app = server.build_app()
    with TestClient(app, raise_server_exceptions=False, base_url=LOOPBACK) as app_client:
        token = _oauth_v1_token(app_client)
        tokenless = _tool_call(app_client, "vault_read", {"path": "test-note.md"})
        wrote = _tool_call(app_client, "vault_write",
                           {"path": "notes/oauth.md", "content": "written by a client"}, token)
        read = _tool_call(app_client, "vault_read", {"path": "notes/oauth.md"}, token)

    assert token.startswith("v1.")
    assert tokenless.status_code == 401
    assert wrote.status_code == 200 and not wrote.json()["result"].get("isError"), wrote.text
    assert (vault_dir / "notes" / "oauth.md").read_text() == "written by a client"
    assert read.status_code == 200 and "written by a client" in read.text, read.text


def _stop_honouring(case, token, monkeypatch):
    """Make a working token unusable in one of the ways a server must notice."""
    if case == "other-resource":
        # The server now answers under another public URL, so it is another resource.
        monkeypatch.setattr(config, "VAULT_MCP_PUBLIC_URL", "https://other.example.xyz")
    elif case == "revoked-by-cli":
        client_id = oauth.get_oauth_state().lookup_access_token(token).client_id
        assert oauth_admin.main(["clients", "revoke", client_id], stdout=StringIO()) == 0
    else:
        state = oauth.get_oauth_state()
        later = time.time() + oauth_state.ACCESS_TOKEN_TTL_SECONDS + 1
        monkeypatch.setattr(state, "_clock", lambda: later)


@pytest.mark.parametrize("case", ["other-resource", "revoked-by-cli", "expired"])
def test_v1_token_is_refused_through_mcp(vault_dir, monkeypatch, case):
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")
    monkeypatch.setattr(config, "VAULT_OAUTH_USERNAME", "obsidian")
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    monkeypatch.setattr(config, "VAULT_MCP_PUBLIC_URL", "")
    monkeypatch.setattr(server.mcp, "_session_manager", None)
    app = server.build_app()
    with TestClient(app, raise_server_exceptions=False, base_url=LOOPBACK) as app_client:
        token = _oauth_v1_token(app_client)
        before = _tool_call(app_client, "vault_read", {"path": "test-note.md"}, token)
        _stop_honouring(case, token, monkeypatch)
        after = _tool_call(app_client, "vault_read", {"path": "test-note.md"}, token)

    assert before.status_code == 200
    assert after.status_code == 401
    assert 'error="invalid_token"' in after.headers["WWW-Authenticate"]
