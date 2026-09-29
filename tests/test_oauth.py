"""Tests for the OAuth authorization flow and its login gate (issues #8 / #29).

These drive the OAuth routes directly (no FastMCP needed) via Starlette's
TestClient. The headline test is `test_exploit_is_closed`: the exact
unauthenticated attack from the bug reports must no longer yield a token.
"""

import base64
import hashlib
import os
import subprocess
import sys

import pytest
from mcp.shared.auth import ProtectedResourceMetadata
from mcp.shared.auth_utils import resource_url_from_server_url
from starlette.applications import Starlette
from starlette.testclient import TestClient

from obsidian_vault_mcp import config, oauth

TOKEN = "test-vault-token-do-not-leak"


@pytest.fixture(autouse=True)
def reset_state(monkeypatch, tmp_path):
    """Fresh in-memory stores + known config for every test."""
    oauth._auth_codes.clear()
    monkeypatch.setattr(config, "VAULT_MCP_TOKEN", TOKEN)
    monkeypatch.setattr(config, "VAULT_OAUTH_USERNAME", "obsidian")
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "")  # unset by default
    monkeypatch.setattr(config, "VAULT_OAUTH_CLIENT_ID", "vault-mcp-client")
    monkeypatch.setattr(config, "VAULT_OAUTH_CLIENT_SECRET", "configured-server-secret")
    monkeypatch.setattr(config, "VAULT_OAUTH_REDIRECT_URIS", [])
    # Persist the client registry to a throwaway path so tests never touch the real
    # on-disk registry.
    monkeypatch.setattr(config, "OAUTH_CLIENTS_PATH", tmp_path / "oauth_clients.json")
    yield


@pytest.fixture
def client():
    app = Starlette(routes=oauth.oauth_routes)
    return TestClient(app)


def _pkce():
    verifier = "verifier-abc123_this-is-long-enough-for-pkce-xyz"
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _register(client, redirect_uri="https://app.example/cb"):
    r = client.post("/oauth/register", json={"client_name": "t", "redirect_uris": [redirect_uri]})
    assert r.status_code == 201
    return r.json()["client_id"], redirect_uri


def _authz_params(client_id, redirect_uri, challenge):
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": "xyz",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }


# --- The reported vulnerability ------------------------------------------------

def test_exploit_is_closed(client):
    """Default config (no password): an anonymous caller must NOT get a token."""
    client_id, redirect = _register(client)
    _, challenge = _pkce()
    # Step 1: hit /authorize like the attacker did -- expect NO code, no redirect.
    r = client.get("/oauth/authorize", params=_authz_params(client_id, redirect, challenge),
                   follow_redirects=False)
    assert r.status_code == 503  # fails closed
    assert "location" not in {k.lower() for k in r.headers}


def test_register_does_not_leak_configured_secret(client):
    r = client.post("/oauth/register", json={"redirect_uris": ["https://app.example/cb"]})
    assert r.status_code == 201
    body = r.json()
    assert body["client_secret"] != config.VAULT_OAUTH_CLIENT_SECRET
    assert body["client_secret"] != config.VAULT_MCP_TOKEN
    assert len(body["client_secret"]) == 64  # freshly generated per-client


# --- The login gate ------------------------------------------------------------

def test_authorize_shows_login_form_when_password_set(client, monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    client_id, redirect = _register(client)
    _, challenge = _pkce()
    r = client.get("/oauth/authorize", params=_authz_params(client_id, redirect, challenge),
                   follow_redirects=False)
    assert r.status_code == 200
    assert 'name="password"' in r.text
    assert "code=" not in (r.headers.get("location") or "")


def test_authorize_rejects_wrong_password(client, monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    client_id, redirect = _register(client)
    _, challenge = _pkce()
    data = _authz_params(client_id, redirect, challenge)
    data.update({"username": "obsidian", "password": "wrong"})
    r = client.post("/oauth/authorize", data=data, follow_redirects=False)
    assert r.status_code == 401
    assert "location" not in {k.lower() for k in r.headers}


def test_full_flow_with_correct_password(client, monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    client_id, redirect = _register(client)
    verifier, challenge = _pkce()
    data = _authz_params(client_id, redirect, challenge)
    data.update({"username": "obsidian", "password": "hunter2"})

    r = client.post("/oauth/authorize", data=data, follow_redirects=False)
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith(redirect)
    code = loc.split("code=")[1].split("&")[0]

    # Exchange the code (with the PKCE verifier) for a token.
    tok = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": redirect, "code_verifier": verifier,
    })
    assert tok.status_code == 200
    body = tok.json()
    assert body["access_token"].startswith("v1.") and body["refresh_token"].startswith("r1.")
    issued = oauth.get_oauth_state().lookup_access_token(body["access_token"])
    assert issued.client_id == client_id


def test_token_requires_pkce_verifier(client, monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    client_id, redirect = _register(client)
    verifier, challenge = _pkce()
    data = _authz_params(client_id, redirect, challenge)
    data.update({"username": "obsidian", "password": "hunter2"})
    r = client.post("/oauth/authorize", data=data, follow_redirects=False)
    code = r.headers["location"].split("code=")[1].split("&")[0]

    # Same code, but NO verifier -> rejected.
    tok = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": redirect,
    })
    assert tok.status_code == 400


# --- Request validation --------------------------------------------------------

def test_unknown_client_rejected(client, monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    _, challenge = _pkce()
    r = client.get("/oauth/authorize",
                   params=_authz_params("bogus-client", "https://app.example/cb", challenge),
                   follow_redirects=False)
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_client"


def test_pkce_required_at_authorize(client, monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    client_id, redirect = _register(client)
    params = _authz_params(client_id, redirect, "")  # empty challenge
    r = client.get("/oauth/authorize", params=params, follow_redirects=False)
    assert r.status_code == 400


def test_open_redirect_rejected(client, monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    client_id, _ = _register(client, redirect_uri="https://app.example/cb")
    _, challenge = _pkce()
    # http non-loopback scheme -> rejected
    r1 = client.get("/oauth/authorize",
                    params=_authz_params(client_id, "http://evil.example/x", challenge),
                    follow_redirects=False)
    assert r1.status_code == 400
    # https but not the registered URI -> rejected
    r2 = client.get("/oauth/authorize",
                    params=_authz_params(client_id, "https://evil.example/cb", challenge),
                    follow_redirects=False)
    assert r2.status_code == 400


# --- Fail-closed: no password means no authorization, by any method -----------

def test_no_password_fails_closed_even_via_post(client):
    """There is no auto-approve escape hatch: without a configured password,
    neither GET nor POST to /authorize can yield a code."""
    client_id, redirect = _register(client)
    _, challenge = _pkce()
    data = _authz_params(client_id, redirect, challenge)
    data.update({"username": "obsidian", "password": "anything"})
    r = client.post("/oauth/authorize", data=data, follow_redirects=False)
    assert r.status_code == 503
    assert "location" not in {k.lower() for k in r.headers}


# --- #4: client identity at token exchange + redirect allowlist ---------------

def _login_and_get_code(client, client_id, redirect, challenge, **extra):
    """Sign in at the authorization endpoint and return the issued code."""
    data = _authz_params(client_id, redirect, challenge)
    data.update({"username": "obsidian", "password": "hunter2", **extra})
    r = client.post("/oauth/authorize", data=data, follow_redirects=False)
    assert r.status_code == 302
    return r.headers["location"].split("code=")[1].split("&")[0]


def test_token_rejects_client_id_mismatch(client, monkeypatch):
    """A code issued to client A cannot be redeemed by client B (RFC 6749 4.1.3)."""
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    client_id, redirect = _register(client)
    other_id, _ = _register(client, redirect_uri="https://other.example/cb")
    verifier, challenge = _pkce()
    code = _login_and_get_code(client, client_id, redirect, challenge)
    tok = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": other_id,
        "redirect_uri": redirect, "code_verifier": verifier,
    })
    assert tok.status_code == 400
    assert tok.json()["error"] == "invalid_grant"


def test_operator_client_redirect_requires_allowlist(client, monkeypatch):
    """The operator-configured client_id no longer accepts an arbitrary redirect_uri;
    it must match VAULT_OAUTH_REDIRECT_URIS (#4a fallthrough closed)."""
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    _, challenge = _pkce()
    op = config.VAULT_OAUTH_CLIENT_ID  # not DCR-registered

    # No allowlist -> any redirect rejected.
    r = client.get("/oauth/authorize",
                   params=_authz_params(op, "https://anywhere.example/cb", challenge),
                   follow_redirects=False)
    assert r.status_code == 400

    # Allowlist set -> only the listed URI is accepted.
    monkeypatch.setattr(config, "VAULT_OAUTH_REDIRECT_URIS", ["https://allowed.example/cb"])
    r_bad = client.get("/oauth/authorize",
                       params=_authz_params(op, "https://anywhere.example/cb", challenge),
                       follow_redirects=False)
    assert r_bad.status_code == 400
    r_ok = client.get("/oauth/authorize",
                      params=_authz_params(op, "https://allowed.example/cb", challenge),
                      follow_redirects=False)
    assert r_ok.status_code == 200  # login form for an allowed redirect


def test_registered_client_empty_redirects_denied(client, monkeypatch):
    """A DCR client that registered no usable (https/loopback) redirect_uris
    cannot use the authorization-code flow (no fallthrough)."""
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    r = client.post("/oauth/register", json={"redirect_uris": ["http://evil.example/cb"]})
    cid = r.json()["client_id"]
    assert r.json()["redirect_uris"] == []  # http non-loopback filtered out
    _, challenge = _pkce()
    r2 = client.get("/oauth/authorize",
                    params=_authz_params(cid, "https://evil.example/cb", challenge),
                    follow_redirects=False)
    assert r2.status_code == 400


# --- #20: RFC 9728 protected-resource metadata --------------------------------

def test_oauth_protected_resource_metadata(client):
    r = client.get("/.well-known/oauth-protected-resource")
    assert r.status_code == 200
    body = r.json()
    assert body["resource"]
    assert isinstance(body["authorization_servers"], list) and body["authorization_servers"]
    assert body["bearer_methods_supported"] == ["header"]


def test_protected_resource_at_root_is_base_url(client, monkeypatch):
    """With the endpoint at "/", resource == base URL (authorization server origin)."""
    monkeypatch.setattr(config, "VAULT_MCP_PATH", "/")
    monkeypatch.setattr(config, "VAULT_MCP_PUBLIC_URL", "https://obsidian.example.xyz")
    body = client.get("/.well-known/oauth-protected-resource").json()
    assert body["resource"] == "https://obsidian.example.xyz"
    assert body["authorization_servers"] == ["https://obsidian.example.xyz"]


def test_protected_resource_includes_subpath(client, monkeypatch):
    """Under a VAULT_MCP_PATH subpath, resource must be the full endpoint URL so
    strict RFC 9728 clients (e.g. Home Assistant) accept it — while the
    authorization server stays the base origin."""
    monkeypatch.setattr(config, "VAULT_MCP_PATH", "/mcp")
    monkeypatch.setattr(config, "VAULT_MCP_PUBLIC_URL", "https://obsidian.example.xyz")
    body = client.get("/.well-known/oauth-protected-resource").json()
    assert body["resource"] == "https://obsidian.example.xyz/mcp"
    assert body["authorization_servers"] == ["https://obsidian.example.xyz"]


def test_protected_resource_path_is_auth_exempt():
    from obsidian_vault_mcp.auth import _AUTH_EXEMPT_PATHS
    assert "/.well-known/oauth-protected-resource" in _AUTH_EXEMPT_PATHS


# --- RFC 8707: a resource names the endpoint, not its spelling -----------------
#
# The official MCP SDK sends the resource in its own rendering: pydantic turns the
# advertised "https://host" into "https://host/", and the SDK lowercases scheme and
# host. Comparing bytes refuses that client. Each side is normalized exactly once,
# because the formula strips one trailing slash: applied twice it would also accept
# "https://host//", which names a different URI.

ROOT = "https://obsidian.example.xyz"
SUBPATH = "https://obsidian.example.xyz/mcp"


def _shouted(uri: str) -> str:
    """The URI with scheme and host in capitals; the path keeps its case."""
    return uri.replace(ROOT, ROOT.upper())


def _sdk_renderings(canonical: str) -> list[str]:
    """The resource as the MCP SDK puts it on the wire, plus a client that shouts."""
    return [
        str(ProtectedResourceMetadata(resource=canonical, authorization_servers=[ROOT]).resource),
        str(ProtectedResourceMetadata(resource=canonical + "/", authorization_servers=[ROOT]).resource),
        resource_url_from_server_url(_shouted(canonical)),
        _shouted(canonical),
    ]


@pytest.mark.parametrize(
    ("provided", "canonical"),
    [
        (ROOT + "//", ROOT),
        (SUBPATH + "//", SUBPATH),
        (SUBPATH, ROOT),
        (SUBPATH + "x", SUBPATH),
        (SUBPATH + "/x", SUBPATH),
        ("https://other.example.xyz/mcp", SUBPATH),
        ("http://obsidian.example.xyz/mcp", SUBPATH),
        ("", SUBPATH),
    ],
    ids=[
        "double-slash-root",
        "double-slash-subpath",
        "subpath-for-root",
        "neighbour-path",
        "path-below",
        "other-host",
        "other-scheme",
        "empty",
    ],
)
def test_other_resources_do_not_match(provided, canonical):
    assert not oauth.resource_matches(provided, canonical)


# --- Code grant: a token pair per client --------------------------------------
#
# A client secret is optional at the token endpoint, as in main: a public client proves
# itself with PKCE alone. A secret that is sent must be the right one.

def _exchange(client, code, client_id, redirect, verifier, **extra):
    """Redeem a code at the token endpoint."""
    return client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": redirect, "code_verifier": verifier, **extra,
    })


def _client_of_kind(client, monkeypatch, kind):
    """A registered or an operator configured client: its id, redirect and secret."""
    if kind == "operator":
        redirect = "https://operator.example/cb"
        monkeypatch.setattr(config, "VAULT_OAUTH_REDIRECT_URIS", [redirect])
        return config.VAULT_OAUTH_CLIENT_ID, redirect, config.VAULT_OAUTH_CLIENT_SECRET
    redirect = "https://app.example/cb"
    registered = client.post("/oauth/register", json={"redirect_uris": [redirect]}).json()
    return registered["client_id"], redirect, registered["client_secret"]


def _refresh(client, refresh_token, client_id, **extra):
    """Spend a refresh token at the token endpoint."""
    return client.post("/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id,
        **extra,
    })


def _client_credentials(client, client_secret, **extra):
    """Ask for a token with the credentials of the operator client."""
    return client.post("/oauth/token", data={
        "grant_type": "client_credentials", "client_id": config.VAULT_OAUTH_CLIENT_ID,
        "client_secret": client_secret, **extra,
    })


@pytest.mark.parametrize("grant", ["authorization_code", "refresh_token"])
@pytest.mark.parametrize("kind", ["registered", "operator"])
def test_code_exchange_rejects_wrong_client_secret(client, monkeypatch, kind, grant):
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    client_id, redirect, secret = _client_of_kind(client, monkeypatch, kind)
    verifier, challenge = _pkce()

    def token_request(sent):
        """The grant under test, sending the given client secret."""
        code = _login_and_get_code(client, client_id, redirect, challenge)
        if grant == "authorization_code":
            return _exchange(client, code, client_id, redirect, verifier, client_secret=sent)
        pair = _exchange(client, code, client_id, redirect, verifier).json()
        return _refresh(client, pair["refresh_token"], client_id, client_secret=sent)

    # Not ASCII on purpose: comparing such text as str raises instead of answering.
    wrong = token_request("не-" + secret)
    right = token_request(secret)

    assert wrong.status_code == 401 and wrong.json()["error"] == "invalid_client"
    assert right.status_code == 200
    issued = oauth.get_oauth_state().lookup_access_token(right.json()["access_token"])
    assert issued.client_id == client_id


def test_client_revoked_between_authorize_and_token(client, monkeypatch):
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    client_id, redirect = _register(client)
    verifier, challenge = _pkce()
    code = _login_and_get_code(client, client_id, redirect, challenge)
    oauth.get_oauth_state().revoke_client(client_id)

    tok = _exchange(client, code, client_id, redirect, verifier)

    assert tok.status_code == 401 and tok.json()["error"] == "invalid_client"


@pytest.mark.parametrize("canonical", [ROOT, SUBPATH], ids=["root", "subpath"])
def test_resource_forms_from_sdk_are_accepted(client, monkeypatch, canonical):
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    monkeypatch.setattr(config, "VAULT_MCP_PUBLIC_URL", ROOT)
    monkeypatch.setattr(config, "VAULT_MCP_PATH", canonical.removeprefix(ROOT) or "/")
    client_id, redirect = _register(client)
    verifier, challenge = _pkce()

    for provided in _sdk_renderings(canonical):
        params = {**_authz_params(client_id, redirect, challenge), "resource": provided}
        form = client.get("/oauth/authorize", params=params)
        assert form.status_code == 200, provided
        assert f'name="resource" value="{provided}"' in form.text, provided
        code = _login_and_get_code(client, client_id, redirect, challenge, resource=provided)
        tok = _exchange(client, code, client_id, redirect, verifier, resource=provided)
        assert tok.status_code == 200, provided
        issued = oauth.get_oauth_state().lookup_access_token(tok.json()["access_token"])
        assert issued.resource == canonical, provided
        refreshed = _refresh(client, tok.json()["refresh_token"], client_id, resource=provided)
        assert refreshed.status_code == 200, provided
        issued = oauth.get_oauth_state().lookup_access_token(refreshed.json()["access_token"])
        assert issued.resource == canonical, provided
        machine = _client_credentials(client, config.VAULT_OAUTH_CLIENT_SECRET, resource=provided)
        assert machine.status_code == 200, provided
        issued = oauth.get_oauth_state().lookup_access_token(machine.json()["access_token"])
        assert issued.resource == canonical, provided


@pytest.mark.parametrize("step", ["authorize", "exchange", "refresh", "client_credentials"])
def test_code_grant_rejects_other_resource(client, monkeypatch, step):
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    monkeypatch.setattr(config, "VAULT_MCP_PUBLIC_URL", ROOT)
    monkeypatch.setattr(config, "VAULT_MCP_PATH", "/mcp")
    client_id, redirect = _register(client)
    verifier, challenge = _pkce()

    if step == "authorize":
        r = client.get("/oauth/authorize",
                       params={**_authz_params(client_id, redirect, challenge), "resource": ROOT})
    elif step == "exchange":
        code = _login_and_get_code(client, client_id, redirect, challenge)
        r = _exchange(client, code, client_id, redirect, verifier, resource=ROOT)
    elif step == "refresh":
        code = _login_and_get_code(client, client_id, redirect, challenge)
        pair = _exchange(client, code, client_id, redirect, verifier).json()
        r = _refresh(client, pair["refresh_token"], client_id, resource=ROOT)
    else:
        r = _client_credentials(client, config.VAULT_OAUTH_CLIENT_SECRET, resource=ROOT)

    assert r.status_code == 400 and r.json()["error"] == "invalid_target"


def test_code_keeps_the_resource_it_was_issued_for(client, monkeypatch):
    # Without a pinned public URL the resource follows the Host header, so a code is
    # redeemed for the resource of its authorization, not of the token request.
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    monkeypatch.setattr(config, "VAULT_MCP_PUBLIC_URL", "")
    monkeypatch.setattr(config, "VAULT_MCP_PATH", "/")
    client_id, redirect = _register(client)
    verifier, challenge = _pkce()
    code = _login_and_get_code(client, client_id, redirect, challenge)

    tok = client.post("/oauth/token", headers={"host": "elsewhere.example"}, data={
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": redirect, "code_verifier": verifier,
    })

    assert tok.status_code == 200
    issued = oauth.get_oauth_state().lookup_access_token(tok.json()["access_token"])
    assert issued.resource == "http://testserver"


# --- Refresh and client credentials -------------------------------------------

def _signed_in_pair(client, monkeypatch):
    """A registered client and the token pair its code grant returned."""
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "hunter2")
    client_id, redirect = _register(client)
    verifier, challenge = _pkce()
    code = _login_and_get_code(client, client_id, redirect, challenge)
    return client_id, _exchange(client, code, client_id, redirect, verifier).json()


def test_refresh_without_secret_rotates(client, monkeypatch):
    client_id, pair = _signed_in_pair(client, monkeypatch)

    rotated = _refresh(client, pair["refresh_token"], client_id)
    replayed = _refresh(client, pair["refresh_token"], client_id)

    assert rotated.status_code == 200
    body = rotated.json()
    assert body["refresh_token"].startswith("r1.")
    assert body["refresh_token"] != pair["refresh_token"]
    issued = oauth.get_oauth_state().lookup_access_token(body["access_token"])
    assert issued.client_id == client_id
    assert replayed.status_code == 400 and replayed.json()["error"] == "invalid_grant"


@pytest.mark.parametrize("missing", ["refresh_token", "client_id"])
def test_refresh_requires_the_token_and_the_client(client, monkeypatch, missing):
    client_id, pair = _signed_in_pair(client, monkeypatch)
    data = {"grant_type": "refresh_token", "refresh_token": pair["refresh_token"],
            "client_id": client_id}
    del data[missing]

    r = client.post("/oauth/token", data=data)

    assert r.status_code == 400 and r.json()["error"] == "invalid_request"


def test_client_credentials_defaults_resource(client, monkeypatch):
    monkeypatch.setattr(config, "VAULT_MCP_PUBLIC_URL", ROOT)
    monkeypatch.setattr(config, "VAULT_MCP_PATH", "/mcp")

    r = _client_credentials(client, config.VAULT_OAUTH_CLIENT_SECRET)

    assert r.status_code == 200
    assert "refresh_token" not in r.json()
    issued = oauth.get_oauth_state().lookup_access_token(r.json()["access_token"])
    assert (issued.client_id, issued.resource) == (config.VAULT_OAUTH_CLIENT_ID, SUBPATH)


@pytest.mark.parametrize(
    "secret", ["wrong-secret", "не-секрет", ""], ids=["wrong", "not-ascii", "empty"]
)
def test_client_credentials_requires_the_configured_secret(client, secret):
    r = _client_credentials(client, secret)

    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


@pytest.mark.parametrize(
    "client_id", ["someone-else", "не-клиент"], ids=["other", "not-ascii"]
)
def test_client_credentials_checks_the_client_id(client, client_id):
    r = client.post("/oauth/token", data={
        "grant_type": "client_credentials", "client_id": client_id,
        "client_secret": config.VAULT_OAUTH_CLIENT_SECRET,
    })

    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


def test_client_credentials_is_for_the_operator_client_only(client):
    body = {"redirect_uris": ["https://app.example/cb"]}
    registered = client.post("/oauth/register", json=body).json()

    r = client.post("/oauth/token", data={
        "grant_type": "client_credentials", "client_id": registered["client_id"],
        "client_secret": registered["client_secret"],
    })

    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


def test_client_credentials_refused_after_revocation(client):
    assert _client_credentials(client, config.VAULT_OAUTH_CLIENT_SECRET).status_code == 200
    oauth.get_oauth_state().revoke_client(config.VAULT_OAUTH_CLIENT_ID)

    r = _client_credentials(client, config.VAULT_OAUTH_CLIENT_SECRET)

    assert r.status_code == 401 and r.json()["error"] == "invalid_client"


def test_metadata_and_registration_announce_refresh(client):
    metadata = client.get("/.well-known/oauth-authorization-server").json()
    body = {"redirect_uris": ["https://app.example/cb"]}
    registered = client.post("/oauth/register", json=body).json()

    assert metadata["grant_types_supported"] == ["authorization_code", "refresh_token"]
    assert metadata["token_endpoint_auth_methods_supported"] == ["client_secret_post", "none"]
    assert registered["grant_types"] == ["authorization_code", "refresh_token"]


# --- Registry persistence across restart --------------------------------------

def _restart():
    """Drop the open store, as a server restart does; the next call reopens it."""
    oauth.close_oauth_state()


def test_registration_persists_across_restart(client):
    """A DCR client survives a server restart via the on-disk store. Without this, a
    restart leaves the connected client replaying a client_id the server no longer
    knows -> 'Invalid or unregistered redirect_uri'."""
    client_id, redirect = _register(client)
    assert oauth._state_path().exists()

    _restart()

    assert oauth._client_known(client_id)
    # redirect_uri validation passes again after the restart, so /oauth/authorize does not answer 400.
    assert oauth._redirect_uri_ok(client_id, redirect) is True


@pytest.mark.skipif(os.name == "nt", reason="file modes are meaningless on Windows")
def test_registry_file_is_owner_only(client):
    """The store holds per-client secret hashes and tokens; it must be 0600."""
    _register(client)
    mode = oauth._state_path().stat().st_mode & 0o777
    assert mode == 0o600


def test_registration_persists_where_there_is_no_fchmod(client, monkeypatch):
    """os.fchmod does not exist on Windows. Calling it bare raised AttributeError while
    the registry was saved, and every client had to re-register after each restart,
    which is what DCR persistence exists to avoid. The attribute goes before the store
    is first opened."""
    monkeypatch.delattr(os, "fchmod", raising=False)

    client_id, _redirect = _register(client)

    assert oauth._state_path().is_file(), "the store was not written"
    _restart()
    assert oauth._client_known(client_id)


def test_load_clients_tolerates_corrupt_file(client):
    """A garbage legacy registry must not crash startup; its import is best-effort."""
    config.OAUTH_CLIENTS_PATH.write_text("{not valid json")

    assert oauth.get_oauth_state().list_clients() == ()


def test_revoked_client_cannot_start_authorization(client):
    client_id, redirect = _register(client)
    oauth.get_oauth_state().revoke_client(client_id)

    r = client.get("/oauth/authorize", params=_authz_params(client_id, redirect, _pkce()[1]))

    assert r.status_code == 400 and r.json()["error"] == "invalid_client"
    assert not oauth._redirect_uri_ok(client_id, redirect)


def test_registration_drops_a_redirect_the_store_cannot_hold(client):
    # Sent as raw JSON: the escape arrives intact and parses to a lone surrogate, which
    # an HTTP client encoding the body itself would refuse to send.
    body = b'{"redirect_uris": ["https://app.example/cb", "https://app.example/cb\\ud800"]}'
    r = client.post("/oauth/register", content=body, headers={"content-type": "application/json"})

    assert r.status_code == 201
    client_id = r.json()["client_id"]
    assert oauth.get_oauth_state().get_client(client_id).redirect_uris == ("https://app.example/cb",)


def test_importing_oauth_opens_no_state(tmp_path):
    registry = tmp_path / "state" / "oauth_clients.json"
    env = {**os.environ, "OAUTH_CLIENTS_PATH": str(registry)}

    done = subprocess.run(
        [sys.executable, "-c", "import obsidian_vault_mcp.oauth"],
        env=env, capture_output=True, text=True, timeout=60,
    )

    assert done.returncode == 0, done.stderr
    assert not registry.parent.exists()


# --- Opening the store at startup ---------------------------------------------

@pytest.fixture
def quiet_serve(vault_dir, monkeypatch):
    """serve() with no index, no uvicorn and no atexit; returns what it registered and ran."""
    import uvicorn

    from obsidian_vault_mcp import server

    seen = {"registered": [], "ran": False, "state_at_run": None}

    def run(*_args, **_kwargs):
        """Stand in for uvicorn: note whether the store is open when serving starts."""
        seen["ran"] = True
        seen["state_at_run"] = oauth._state

    monkeypatch.setattr(uvicorn, "run", run)
    monkeypatch.setattr(server, "VAULT_PATH", vault_dir)
    monkeypatch.setattr(server.frontmatter_index, "start", lambda: None)
    monkeypatch.setattr(server.frontmatter_index, "stop", lambda: None)
    registered = seen["registered"]
    monkeypatch.setattr(server.atexit, "register", lambda fn, *a, **k: registered.append(fn))
    return server, seen


def test_serve_opens_the_oauth_state_before_serving(quiet_serve):
    server, seen = quiet_serve

    server.serve()

    assert seen["state_at_run"] is not None
    assert oauth._state_path().is_file()
    assert oauth.close_oauth_state in seen["registered"]


def test_cf_mode_serve_creates_no_state_files(quiet_serve, monkeypatch):
    from obsidian_vault_mcp import cf_access

    server, seen = quiet_serve
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "myteam.cloudflareaccess.com")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "test-aud")
    monkeypatch.setattr(cf_access, "require_dependencies", lambda: None)
    monkeypatch.setattr(cf_access, "warm_jwks", lambda: None)

    server.serve()

    assert seen["ran"] and seen["state_at_run"] is None
    assert not list(config.OAUTH_CLIENTS_PATH.parent.glob("oauth_state*"))


def test_serve_refuses_to_start_without_its_oauth_state(quiet_serve, monkeypatch, tmp_path):
    server, seen = quiet_serve
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    monkeypatch.setattr(config, "OAUTH_CLIENTS_PATH", blocker / "oauth_clients.json")

    with pytest.raises(SystemExit) as exited:
        server.serve()

    assert exited.value.code == 1
    assert not seen["ran"]
