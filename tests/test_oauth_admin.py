"""Metadata-only local OAuth operator CLI contracts."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from io import StringIO
from pathlib import Path

from obsidian_vault_mcp import oauth_admin
from obsidian_vault_mcp.oauth_state import OAuthState

RESOURCE = "https://vault.example.test"
REDIRECT = "https://client.example.test/callback"


def _state(tmp_path: Path) -> OAuthState:
    vault = tmp_path / "vault"
    vault.mkdir(mode=0o700, exist_ok=True)
    return OAuthState(
        tmp_path / "state" / "oauth.sqlite3",
        vault_path=vault,
        legacy_path=tmp_path / "legacy" / "clients.json",
        access_token_ttl_seconds=3_600,
        refresh_token_ttl_seconds=7_200,
    )


def _args(tmp_path: Path) -> list[str]:
    return [
        "--state-path",
        str(tmp_path / "state" / "oauth.sqlite3"),
        "--vault-path",
        str(tmp_path / "vault"),
        "--legacy-path",
        str(tmp_path / "legacy" / "clients.json"),
        "--access-token-ttl-seconds",
        "3600",
        "--refresh-token-ttl-seconds",
        "7200",
    ]


def _run(tmp_path: Path, *command: str) -> tuple[int, object, str]:
    stdout = StringIO()
    stderr = StringIO()
    result = oauth_admin.main(
        [*_args(tmp_path), *command], stdout=stdout, stderr=stderr
    )
    payload = json.loads(stdout.getvalue()) if stdout.getvalue() else None
    return result, payload, stderr.getvalue()


def _issue_via_code(state: OAuthState) -> tuple:
    registered = state.register_client([REDIRECT])
    verifier = "admin-cli-pkce-verifier-marker"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    code = state.issue_authorization_code(
        client_id=registered.client.client_id,
        redirect_uri=REDIRECT,
        code_challenge=challenge,
        resource=RESOURCE,
    )
    issued = state.redeem_authorization_code(
        code=code,
        client_id=registered.client.client_id,
        client_secret=registered.client_secret,
        redirect_uri=REDIRECT,
        code_verifier=verifier,
        resource=RESOURCE,
    )
    return registered, issued


def test_client_inventory_and_revoke_are_metadata_only(tmp_path):
    state = _state(tmp_path)
    registered = state.register_client([REDIRECT], client_name="CLI test")
    client_id = registered.client.client_id
    client_secret = registered.client_secret
    state.close()

    result, payload, stderr = _run(tmp_path, "clients", "list")

    assert result == 0
    assert stderr == ""
    assert payload == [
        {
            "client_id": client_id,
            "client_name": "CLI test",
            "created_at": registered.client.created_at,
            "is_static": False,
            "last_authorized_at": None,
            "redirect_uris": [REDIRECT],
            "revoked_at": None,
        }
    ]
    assert client_secret not in json.dumps(payload)

    result, revoked, _ = _run(tmp_path, "clients", "revoke", client_id)
    assert result == 0
    assert revoked == {"client_id": client_id, "revoked": True}

    reopened = _state(tmp_path)
    assert reopened.get_client(client_id).revoked_at is not None
    reopened.close()


def test_token_inventory_filter_and_revoke_never_expose_bearer(tmp_path):
    state = _state(tmp_path)
    first = state.register_client([REDIRECT])
    second = state.register_client(["https://second.example.test/cb"])
    first_token = state.issue_access_token(
        client_id=first.client.client_id,
        resource=RESOURCE,
    )
    state.issue_access_token(
        client_id=second.client.client_id,
        resource=RESOURCE,
    )
    state.close()

    result, payload, stderr = _run(
        tmp_path,
        "tokens",
        "list",
        "--client-id",
        first.client.client_id,
    )

    assert result == 0
    assert stderr == ""
    assert len(payload) == 1
    assert payload[0]["token_id"] == first_token.token.token_id
    assert set(payload[0]) == {
        "client_id",
        "expires_at",
        "issued_at",
        "resource",
        "revoked_at",
        "token_id",
    }
    serialized = json.dumps(payload)
    assert first_token.access_token not in serialized
    assert first_token.access_token.split(".")[-1] not in serialized

    result, revoked, _ = _run(tmp_path, "tokens", "revoke", first_token.token.token_id)
    assert result == 0
    assert revoked == {
        "revoked": True,
        "token_id": first_token.token.token_id,
    }


def test_refresh_inventory_and_revoke(tmp_path):
    state = _state(tmp_path)
    registered, issued = _issue_via_code(state)
    client_id = registered.client.client_id
    state.close()

    result, payload, stderr = _run(tmp_path, "refresh", "list")

    assert result == 0
    assert stderr == ""
    assert len(payload) == 1
    assert payload[0]["token_id"] == issued.refresh.token_id
    assert payload[0]["access_token_id"] == issued.token.token_id
    assert payload[0]["client_id"] == client_id
    serialized = json.dumps(payload)
    assert issued.refresh_token not in serialized
    assert issued.refresh_token.split(".")[-1] not in serialized

    result, revoked, _ = _run(tmp_path, "refresh", "revoke", issued.refresh.token_id)
    assert result == 0
    assert revoked == {"revoked": True, "token_id": issued.refresh.token_id}

    reopened = _state(tmp_path)
    assert reopened.lookup_access_token(issued.access_token) is None
    assert reopened.lookup_refresh_token(issued.refresh_token) is None
    reopened.close()


def test_migrate_imports_legacy_file_once_and_removes_it(tmp_path):
    legacy_path = tmp_path / "legacy" / "clients.json"
    legacy_path.parent.mkdir(mode=0o700)
    legacy_path.write_text(
        json.dumps(
            {
                "legacy-client": {
                    "client_secret": "legacy-secret",
                    "redirect_uris": [REDIRECT],
                    "created_at": 1.0,
                }
            }
        )
    )
    legacy_path.chmod(0o600)

    result, payload, stderr = _run(tmp_path, "migrate")

    assert result == 0
    assert stderr == ""
    assert payload == {"migrated": True}
    assert not legacy_path.exists()

    state = _state(tmp_path)
    migrated = state.get_client("legacy-client")
    assert migrated is not None
    assert state.verify_client_secret("legacy-client", "legacy-secret")
    state.close()

    result, payload, _ = _run(tmp_path, "migrate")
    assert result == 0
    assert payload == {"migrated": True}


def test_metadata_command_does_not_consume_pending_legacy_migration(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir(mode=0o700)
    legacy_path = tmp_path / "legacy" / "clients.json"
    legacy_path.parent.mkdir(mode=0o700)
    legacy_path.write_text(
        json.dumps(
            {
                "pending-client": {
                    "client_secret": "pending-secret",
                    "redirect_uris": [REDIRECT],
                }
            }
        )
    )
    legacy_path.chmod(0o600)

    result, payload, stderr = _run(tmp_path, "clients", "list")

    assert result == 0
    assert stderr == ""
    assert payload == []
    assert legacy_path.exists()
    with sqlite3.connect(tmp_path / "state" / "oauth.sqlite3") as connection:
        assert connection.execute(
            "SELECT count(*) FROM migration_metadata"
        ).fetchone() == (0,)
