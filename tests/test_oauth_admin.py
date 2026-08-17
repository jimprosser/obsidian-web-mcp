"""Metadata-only local OAuth operator CLI contracts."""

from __future__ import annotations

import json
import sqlite3
from io import StringIO
from pathlib import Path

from obsidian_vault_mcp import oauth_admin
from obsidian_vault_mcp.oauth_state import (
    VAULT_READONLY_CAPABILITIES,
    VAULT_READONLY_V1,
    OAuthState,
)

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
    ]


def _run(tmp_path: Path, *command: str) -> tuple[int, object, str]:
    stdout = StringIO()
    stderr = StringIO()
    result = oauth_admin.main(
        [*_args(tmp_path), *command], stdout=stdout, stderr=stderr
    )
    payload = json.loads(stdout.getvalue()) if stdout.getvalue() else None
    return result, payload, stderr.getvalue()


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
            "policy": VAULT_READONLY_V1,
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
    assert payload[0]["capabilities"] == list(VAULT_READONLY_CAPABILITIES)
    serialized = json.dumps(payload)
    assert first_token.access_token not in serialized
    assert first_token.access_token.split(".")[-1] not in serialized

    result, revoked, _ = _run(tmp_path, "tokens", "revoke", first_token.token.token_id)
    assert result == 0
    assert revoked == {
        "revoked": True,
        "token_id": first_token.token.token_id,
    }


def test_backup_is_online_reopenable_and_secret_free(tmp_path):
    state = _state(tmp_path)
    registered = state.register_client([REDIRECT])
    issued = state.issue_access_token(
        client_id=registered.client.client_id,
        resource=RESOURCE,
    )
    state.close()
    backup = tmp_path / "backup" / "oauth.sqlite3"

    result, payload, stderr = _run(tmp_path, "backup", str(backup))

    assert result == 0
    assert stderr == ""
    assert payload == {"backup": str(backup)}
    with sqlite3.connect(backup) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM clients").fetchone()[0] == 1
        assert (
            connection.execute("SELECT count(*) FROM access_tokens").fetchone()[0] == 1
        )
    backup_bytes = backup.read_bytes()
    assert registered.client_secret.encode() not in backup_bytes
    assert issued.access_token.encode() not in backup_bytes


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
