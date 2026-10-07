"""Brakes on failed logins and on client registration (#97).

Before: 200 wrong passwords in 2.3 s, then the right one was accepted; registration had
no cap, and every registration grows oauth_clients.json. Both limits are global, on by
default, and constants. Everything goes through build_app(), the app the server runs.
"""

import base64
import hashlib

import pytest
from starlette.testclient import TestClient

from obsidian_vault_mcp import config, oauth
from obsidian_vault_mcp.server import build_app

REDIRECT = "https://app.example/cb"
VERIFIER = "verifier-abc123_this-is-long-enough-for-pkce-xyz"
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(oauth, "_clock", lambda: now[0])
    return now


@pytest.fixture
def app(vault_dir, monkeypatch, tmp_path, clock):
    oauth._clients.clear()
    oauth._auth_codes.clear()
    monkeypatch.setattr(config, "VAULT_OAUTH_USERNAME", "owner")
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "correct-horse")
    monkeypatch.setattr(config, "OAUTH_CLIENTS_PATH", tmp_path / "oauth_clients.json")
    yield TestClient(build_app(), base_url="https://vault.example")
    oauth._clients.clear()


def register(client):
    return client.post("/oauth/register", json={"client_name": "t", "redirect_uris": [REDIRECT]})


def login(client, client_id, password):
    data = {"response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "state": "s",
            "code_challenge": CHALLENGE, "code_challenge_method": "S256",
            "username": "owner", "password": password}
    return client.post("/oauth/authorize", data=data, follow_redirects=False)


def test_failed_logins_below_the_limit_are_plain_refusals(app):
    """Control: a mistyped password is a 401 and the next correct one works."""
    cid = register(app).json()["client_id"]
    for _ in range(oauth.LOGIN_FAILURE_LIMIT - 1):
        assert login(app, cid, "wrong").status_code == 401

    assert login(app, cid, "correct-horse").status_code == 302


def test_the_limit_trips_with_429_and_retry_after(app):
    cid = register(app).json()["client_id"]
    for _ in range(oauth.LOGIN_FAILURE_LIMIT):
        assert login(app, cid, "wrong").status_code == 401

    tripped = login(app, cid, "wrong")

    assert tripped.status_code == 429
    assert 0 < int(tripped.headers["Retry-After"]) <= oauth.LOGIN_FAILURE_WINDOW_SECONDS
    assert "Too many failed sign-in attempts" in tripped.text


def test_the_correct_password_is_refused_while_tripped(app):
    cid = register(app).json()["client_id"]
    for _ in range(oauth.LOGIN_FAILURE_LIMIT):
        login(app, cid, "wrong")

    response = login(app, cid, "correct-horse")

    assert response.status_code == 429
    assert "code=" not in (response.headers.get("location") or "")


def test_login_works_again_after_the_window(app, clock):
    cid = register(app).json()["client_id"]
    for _ in range(oauth.LOGIN_FAILURE_LIMIT):
        login(app, cid, "wrong")
    assert login(app, cid, "correct-horse").status_code == 429

    clock[0] += oauth.LOGIN_FAILURE_WINDOW_SECONDS + 1

    assert login(app, cid, "correct-horse").status_code == 302


def test_the_limit_is_global_not_per_address(app):
    """Switching the source address does not reset the count."""
    cid = register(app).json()["client_id"]
    for i in range(oauth.LOGIN_FAILURE_LIMIT):
        app.headers["X-Forwarded-For"] = f"203.0.113.{i}"
        login(app, cid, "wrong")
    app.headers["X-Forwarded-For"] = "198.51.100.7"

    assert login(app, cid, "correct-horse").status_code == 429


def test_showing_the_form_is_not_limited(app):
    """Only attempts count and only attempts are refused; the GET still renders."""
    cid = register(app).json()["client_id"]
    for _ in range(oauth.LOGIN_FAILURE_LIMIT):
        login(app, cid, "wrong")

    form = app.get("/oauth/authorize", params={"response_type": "code", "client_id": cid, "redirect_uri": REDIRECT,
                                                "state": "s", "code_challenge": CHALLENGE, "code_challenge_method": "S256"})

    assert form.status_code == 200


def test_registration_is_capped_and_nothing_more_is_saved(app, clock, tmp_path):
    for _ in range(oauth.REGISTRATION_LIMIT):
        assert register(app).status_code == 201
    saved = (tmp_path / "oauth_clients.json").read_bytes()

    refused = register(app)

    assert refused.status_code == 429 and refused.json()["error"] == "too_many_requests"
    assert int(refused.headers["Retry-After"]) > 0
    assert (tmp_path / "oauth_clients.json").read_bytes() == saved
    assert len(oauth._clients) == oauth.REGISTRATION_LIMIT

    clock[0] += oauth.REGISTRATION_WINDOW_SECONDS + 1
    assert register(app).status_code == 201


def test_the_token_endpoint_is_not_limited(app):
    """Out of scope by decision: client secrets are 256-bit random."""
    for _ in range(oauth.LOGIN_FAILURE_LIMIT + 5):
        r = app.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": "x", "client_secret": "y"})
        assert r.status_code != 429


def test_the_unused_constants_are_gone():
    assert not hasattr(config, "RATE_LIMIT_READ") and not hasattr(config, "RATE_LIMIT_WRITE")
