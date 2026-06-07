"""Tests for the OAuth authorization flow and its login gate (issues #8 / #29).

These drive the OAuth routes directly (no FastMCP needed) via Starlette's
TestClient. The headline test is `test_exploit_is_closed`: the exact
unauthenticated attack from the bug reports must no longer yield a token.
"""

import base64
import hashlib

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from obsidian_vault_mcp import config, oauth

TOKEN = "test-vault-token-do-not-leak"


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    """Fresh in-memory stores + known config for every test."""
    oauth._clients.clear()
    oauth._auth_codes.clear()
    monkeypatch.setattr(config, "VAULT_MCP_TOKEN", TOKEN)
    monkeypatch.setattr(config, "VAULT_OAUTH_USERNAME", "obsidian")
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "")  # unset by default
    monkeypatch.setattr(config, "VAULT_OAUTH_CLIENT_ID", "vault-mcp-client")
    monkeypatch.setattr(config, "VAULT_OAUTH_CLIENT_SECRET", "configured-server-secret")
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
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": redirect, "code_verifier": verifier,
    })
    assert tok.status_code == 200
    assert tok.json()["access_token"] == TOKEN


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
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
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
