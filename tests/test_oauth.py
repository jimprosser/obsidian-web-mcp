"""Tests for the vault MCP server's OAuth 2.0 endpoints."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import urllib.parse
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from obsidian_vault_mcp import config, oauth
from obsidian_vault_mcp.oauth_state import (
    REAUTHORIZATION_REQUIRED,
    VAULT_READONLY_V1,
)

MASTER_TOKEN = "master-bearer-must-not-be-issued"
STATIC_CLIENT_ID = "test-static-client"
STATIC_CLIENT_SECRET = "test-static-secret"
LOGIN_USERNAME = "test-user"
LOGIN_PASSWORD = "test-pass"
RESOURCE = "https://vault.example.test"
STATIC_REDIRECT = "https://operator.example.test/callback"
DYNAMIC_REDIRECT = "https://client.example.test/callback"


@pytest.fixture(autouse=True)
def reset_state(monkeypatch, tmp_path: Path):
    oauth.close_oauth_state()
    vault_path = tmp_path / "vault"
    vault_path.mkdir(mode=0o700)
    monkeypatch.setattr(config, "VAULT_PATH", vault_path)
    monkeypatch.setattr(config, "VAULT_MCP_TOKEN", MASTER_TOKEN)
    monkeypatch.setattr(config, "VAULT_OAUTH_USERNAME", LOGIN_USERNAME)
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", LOGIN_PASSWORD)
    monkeypatch.setattr(config, "VAULT_OAUTH_CLIENT_ID", STATIC_CLIENT_ID)
    monkeypatch.setattr(config, "VAULT_OAUTH_CLIENT_SECRET", STATIC_CLIENT_SECRET)
    monkeypatch.setattr(config, "VAULT_OAUTH_REDIRECT_URIS", [STATIC_REDIRECT])
    monkeypatch.setattr(config, "VAULT_MCP_PUBLIC_URL", RESOURCE)
    monkeypatch.setattr(
        config, "VAULT_OAUTH_STATE_PATH", tmp_path / "state" / "oauth.sqlite3"
    )
    monkeypatch.setattr(
        config, "OAUTH_CLIENTS_PATH", tmp_path / "legacy" / "clients.json"
    )
    monkeypatch.setattr(config, "VAULT_OAUTH_APPROVED_LEGACY_CLIENT_IDS", frozenset())
    monkeypatch.setattr(config, "oauth_access_token_ttl_seconds", lambda: 3_600)
    yield
    oauth.close_oauth_state()


@pytest.fixture
def client() -> TestClient:
    app = Starlette(routes=oauth.oauth_routes)
    return TestClient(app)


def _pkce() -> tuple[str, str]:
    verifier = "test-pkce-verifier-that-is-long-enough"
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _register(
    client: TestClient, redirect_uri: str = DYNAMIC_REDIRECT
) -> tuple[str, str, str]:
    response = client.post(
        "/oauth/register",
        json={
            "client_name": "Test Client",
            "redirect_uris": [redirect_uri],
        },
    )
    assert response.status_code == 201
    body = response.json()
    return body["client_id"], body["client_secret"], redirect_uri


def _write_pending_legacy_client() -> tuple[str, str, str]:
    client_id = "pending-legacy-client"
    client_secret = "pending-legacy-secret"
    redirect_uri = "https://pending.example.test/callback"
    source = config.OAUTH_CLIENTS_PATH
    source.parent.mkdir(mode=0o700, parents=True)
    source.write_text(
        json.dumps(
            {
                client_id: {
                    "client_secret": client_secret,
                    "redirect_uris": [redirect_uri],
                    "created_at": 1.0,
                }
            }
        )
    )
    source.chmod(0o600)
    return client_id, client_secret, redirect_uri


def _authz_params(client_id: str, redirect_uri: str) -> dict[str, str]:
    _, challenge = _pkce()
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": "xyz",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": RESOURCE,
    }


def _authorize(
    client: TestClient,
    client_id: str,
    redirect_uri: str,
) -> str:
    params = _authz_params(client_id, redirect_uri)
    response = client.post(
        "/oauth/authorize",
        data={
            **params,
            "username": LOGIN_USERNAME,
            "password": LOGIN_PASSWORD,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    query = urllib.parse.parse_qs(
        urllib.parse.urlsplit(response.headers["location"]).query
    )
    assert query["state"] == ["xyz"]
    return query["code"][0]


def _exchange(
    client: TestClient,
    *,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    verifier: str | None = None,
    resource: str = RESOURCE,
):
    if verifier is None:
        verifier, _ = _pkce()
    return client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "resource": resource,
        },
    )


def test_registration_returns_per_client_secret_and_persists(client):
    client_id, client_secret, redirect_uri = _register(client)

    assert client_id.startswith("vault-mcp-")
    assert len(client_secret) == 64
    assert client_secret not in {STATIC_CLIENT_SECRET, MASTER_TOKEN}
    assert oauth.get_oauth_state().client_redirect_uri_allowed(client_id, redirect_uri)

    oauth.close_oauth_state()
    reopened = oauth.get_oauth_state()
    assert reopened.verify_client_secret(client_id, client_secret)
    assert reopened.client_redirect_uri_allowed(client_id, redirect_uri)


def test_two_dynamic_clients_receive_independent_access_tokens(client):
    first_id, first_secret, first_redirect = _register(client)
    second_id, second_secret, second_redirect = _register(
        client, "https://second.example.test/callback"
    )
    first_code = _authorize(client, first_id, first_redirect)
    second_code = _authorize(client, second_id, second_redirect)

    first = _exchange(
        client,
        code=first_code,
        client_id=first_id,
        client_secret=first_secret,
        redirect_uri=first_redirect,
    )
    second = _exchange(
        client,
        code=second_code,
        client_id=second_id,
        client_secret=second_secret,
        redirect_uri=second_redirect,
    )

    assert first.status_code == 200
    assert second.status_code == 200
    first_token = first.json()["access_token"]
    second_token = second.json()["access_token"]
    assert first_token != second_token
    assert MASTER_TOKEN not in {first_token, second_token}
    assert first.json()["expires_in"] == 3_600
    assert "refresh_token" not in first.json()


def test_authorization_code_survives_state_reopen(client):
    client_id, client_secret, redirect_uri = _register(client)
    code = _authorize(client, client_id, redirect_uri)

    oauth.close_oauth_state()
    response = _exchange(
        client,
        code=code,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )

    assert response.status_code == 200
    assert response.json()["access_token"].startswith("v1.")


def test_wrong_client_secret_does_not_consume_code(client):
    client_id, client_secret, redirect_uri = _register(client)
    code = _authorize(client, client_id, redirect_uri)

    denied = _exchange(
        client,
        code=code,
        client_id=client_id,
        client_secret="wrong",
        redirect_uri=redirect_uri,
    )
    accepted = _exchange(
        client,
        code=code,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )

    assert denied.status_code == 401
    assert denied.json()["error"] == "invalid_client"
    assert accepted.status_code == 200


def test_invalid_exchange_inputs_do_not_consume_code(client):
    client_id, client_secret, redirect_uri = _register(client)
    code = _authorize(client, client_id, redirect_uri)

    bad_pkce = _exchange(
        client,
        code=code,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        verifier="wrong",
    )
    bad_resource = _exchange(
        client,
        code=code,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        resource="https://wrong.example.test",
    )
    accepted = _exchange(
        client,
        code=code,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )

    assert bad_pkce.status_code == 400
    assert bad_pkce.json()["error"] == "invalid_grant"
    assert bad_resource.status_code == 400
    assert bad_resource.json()["error"] == "invalid_target"
    assert accepted.status_code == 200


def test_static_authorization_code_uses_configured_secret(client):
    code = _authorize(client, STATIC_CLIENT_ID, STATIC_REDIRECT)

    denied = _exchange(
        client,
        code=code,
        client_id=STATIC_CLIENT_ID,
        client_secret="wrong",
        redirect_uri=STATIC_REDIRECT,
    )
    accepted = _exchange(
        client,
        code=code,
        client_id=STATIC_CLIENT_ID,
        client_secret=STATIC_CLIENT_SECRET,
        redirect_uri=STATIC_REDIRECT,
    )

    assert denied.status_code == 401
    assert accepted.status_code == 200
    assert accepted.json()["access_token"] != MASTER_TOKEN


def test_client_credentials_issues_independent_tokens_and_honors_revoke(client):
    request = {
        "grant_type": "client_credentials",
        "client_id": STATIC_CLIENT_ID,
        "client_secret": STATIC_CLIENT_SECRET,
        "resource": RESOURCE,
    }
    first = client.post("/oauth/token", data=request)
    second = client.post("/oauth/token", data=request)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["access_token"] != second.json()["access_token"]
    assert MASTER_TOKEN not in {
        first.json()["access_token"],
        second.json()["access_token"],
    }

    assert oauth.get_oauth_state().revoke_client(STATIC_CLIENT_ID)
    oauth.close_oauth_state()
    denied = client.post("/oauth/token", data=request)
    assert denied.status_code == 401
    assert denied.json()["error"] == "invalid_client"


def test_client_credentials_rejects_wrong_secret_and_resource(client):
    wrong_secret = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": STATIC_CLIENT_ID,
            "client_secret": "wrong",
            "resource": RESOURCE,
        },
    )
    wrong_resource = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": STATIC_CLIENT_ID,
            "client_secret": STATIC_CLIENT_SECRET,
            "resource": "https://wrong.example.test",
        },
    )

    assert wrong_secret.status_code == 401
    assert wrong_secret.json()["error"] == "invalid_client"
    assert wrong_resource.status_code == 400
    assert wrong_resource.json()["error"] == "invalid_target"


def test_authorize_requires_interactive_login(client):
    client_id, _, redirect_uri = _register(client)
    params = _authz_params(client_id, redirect_uri)

    get_response = client.get("/oauth/authorize", params=params)
    wrong_response = client.post(
        "/oauth/authorize",
        data={**params, "username": LOGIN_USERNAME, "password": "wrong"},
        follow_redirects=False,
    )

    assert get_response.status_code == 200
    assert "<form" in get_response.text
    assert wrong_response.status_code == 401
    assert "location" not in wrong_response.headers


def test_missing_login_configuration_fails_closed(client, monkeypatch):
    client_id, _, redirect_uri = _register(client)
    params = _authz_params(client_id, redirect_uri)
    monkeypatch.setattr(config, "VAULT_OAUTH_PASSWORD", "")

    get_response = client.get("/oauth/authorize", params=params, follow_redirects=False)
    post_response = client.post(
        "/oauth/authorize",
        data={**params, "username": LOGIN_USERNAME, "password": "anything"},
        follow_redirects=False,
    )

    assert get_response.status_code == 503
    assert post_response.status_code == 503
    assert "location" not in get_response.headers
    assert "location" not in post_response.headers


def test_pending_import_requires_fresh_login_then_issues_exact_readonly_token(client):
    client_id, client_secret, redirect_uri = _write_pending_legacy_client()
    state = oauth.initialize_oauth_state()
    params = _authz_params(client_id, redirect_uri)

    denied = client.post(
        "/oauth/authorize",
        data={**params, "username": LOGIN_USERNAME, "password": "wrong"},
        follow_redirects=False,
    )
    assert denied.status_code == 401
    assert state.get_client(client_id).policy == REAUTHORIZATION_REQUIRED

    code = _authorize(client, client_id, redirect_uri)
    accepted = _exchange(
        client,
        code=code,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )

    assert accepted.status_code == 200
    assert state.get_client(client_id).policy == VAULT_READONLY_V1
    token_id = accepted.json()["access_token"].split(".")[1]
    token = next(item for item in state.list_tokens() if item.token_id == token_id)
    assert token.policy == VAULT_READONLY_V1
    assert token.capabilities == (
        "vault_batch_read",
        "vault_list",
        "vault_read",
        "vault_search",
        "vault_search_frontmatter",
    )


def test_reauthorization_rolls_back_if_code_insert_fails(client):
    client_id, _, redirect_uri = _write_pending_legacy_client()
    state = oauth.initialize_oauth_state()
    state._connection.execute(
        "CREATE TRIGGER fail_code_insert BEFORE INSERT ON authorization_codes "
        "BEGIN SELECT RAISE(ABORT, 'synthetic code insert failure'); END"
    )

    with pytest.raises(sqlite3.IntegrityError, match="synthetic code insert failure"):
        client.post(
            "/oauth/authorize",
            data={
                **_authz_params(client_id, redirect_uri),
                "username": LOGIN_USERNAME,
                "password": LOGIN_PASSWORD,
            },
            follow_redirects=False,
        )

    assert state.get_client(client_id).policy == REAUTHORIZATION_REQUIRED


@pytest.mark.parametrize(
    "changes,error",
    [
        ({"response_type": "token"}, "unsupported_response_type"),
        ({"client_id": "unknown-client"}, "invalid_client"),
        ({"redirect_uri": "https://evil.example.test/callback"}, "invalid_request"),
        ({"code_challenge": ""}, "invalid_request"),
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"resource": "https://wrong.example.test"}, "invalid_target"),
    ],
)
def test_authorization_request_validation(client, changes, error):
    client_id, _, redirect_uri = _register(client)
    params = _authz_params(client_id, redirect_uri)
    params.update(changes)

    response = client.get("/oauth/authorize", params=params)

    assert response.status_code == 400
    assert response.json()["error"] == error


def test_registration_filters_unsafe_redirects(client):
    response = client.post(
        "/oauth/register",
        json={
            "redirect_uris": [
                "http://evil.example.test/callback",
                "http://localhost:1234/callback",
                "https://safe.example.test/callback",
            ]
        },
    )

    assert response.status_code == 201
    assert response.json()["redirect_uris"] == [
        "http://localhost:1234/callback",
        "https://safe.example.test/callback",
    ]


def test_registration_with_no_safe_redirect_cannot_authorize(client):
    client_id, _, _ = _register(client, "http://evil.example.test/callback")
    params = _authz_params(client_id, "http://evil.example.test/callback")

    response = client.get("/oauth/authorize", params=params)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_oauth_metadata_advertises_confidential_code_flow(client):
    response = client.get("/.well-known/oauth-authorization-server")

    assert response.status_code == 200
    body = response.json()
    assert body["issuer"] == RESOURCE
    assert body["resource"] == RESOURCE
    assert body["token_endpoint_auth_methods_supported"] == ["client_secret_post"]
    assert set(body["grant_types_supported"]) == {
        "authorization_code",
        "client_credentials",
    }


def test_protected_resource_metadata_uses_canonical_resource(client):
    response = client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    assert response.json() == {
        "resource": RESOURCE,
        "authorization_servers": [RESOURCE],
        "bearer_methods_supported": ["header"],
    }
