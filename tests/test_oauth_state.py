"""Persistent OAuth credential lifecycle contracts."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from obsidian_vault_mcp.oauth_state import (
    LEGACY_FULL,
    REAUTHORIZATION_REQUIRED,
    VAULT_READONLY_CAPABILITIES,
    VAULT_READONLY_V1,
    InvalidClient,
    InvalidGrant,
    InvalidTarget,
    OAuthState,
    UnsafeStatePath,
)

DYNAMIC_SECRET = "dynamic-client-secret-marker"
STATIC_SECRET = "static-client-secret-marker"
TOKEN_SECRET = "access-token-secret-marker"
MASTER_SECRET = "master-bearer-marker"
LOGIN_SECRET = "interactive-login-marker"
RESOURCE = "https://vault.example.test"
REDIRECT = "https://client.example.test/callback"
VERIFIER = "pkce-verifier-marker"
CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest())
    .rstrip(b"=")
    .decode()
)


@pytest.fixture
def state_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    vault = tmp_path / "vault"
    vault.mkdir(mode=0o700)
    state_path = tmp_path / "state" / "oauth_state.sqlite3"
    legacy_path = tmp_path / "legacy" / "oauth_clients.json"
    return vault, state_path, legacy_path


def _state(
    state_paths: tuple[Path, Path, Path],
    *,
    now: list[float] | None = None,
    approved: frozenset[str] = frozenset(),
    static_secret: str = STATIC_SECRET,
) -> OAuthState:
    vault, state_path, legacy_path = state_paths
    clock = (lambda: now[0]) if now is not None else None
    state = OAuthState(
        state_path,
        vault_path=vault,
        legacy_path=legacy_path,
        approved_legacy_client_ids=approved,
        access_token_ttl_seconds=60,
        clock=clock,
        static_client_authenticator=lambda client_id, secret: (
            client_id == "static-client" and secrets_equal(secret, static_secret)
        ),
    )
    state.migrate_legacy()
    return state


def secrets_equal(left: str, right: str) -> bool:
    """Keep static-secret expectations independent of production helpers."""
    import hmac

    return hmac.compare_digest(left, right)


def _register(state: OAuthState) -> tuple[str, str]:
    issued = state.register_client([REDIRECT])
    return issued.client.client_id, issued.client_secret


def _issue_code(state: OAuthState, client_id: str) -> str:
    return state.issue_authorization_code(
        client_id=client_id,
        redirect_uri=REDIRECT,
        code_challenge=CHALLENGE,
        resource=RESOURCE,
    )


def _redeem(
    state: OAuthState,
    code: str,
    client_id: str,
    client_secret: str,
):
    return state.redeem_authorization_code(
        code=code,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=REDIRECT,
        code_verifier=VERIFIER,
        resource=RESOURCE,
    )


def _write_legacy(path: Path, records: dict[str, dict]) -> None:
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_text(json.dumps(records))
    path.chmod(0o600)


def _db_text(path: Path) -> str:
    chunks = [path.read_bytes()]
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists():
            chunks.append(sidecar.read_bytes())
    return b"".join(chunks).decode("utf-8", errors="ignore")


def test_readonly_policy_has_exact_closed_capability_set():
    assert VAULT_READONLY_CAPABILITIES == (
        "vault_batch_read",
        "vault_list",
        "vault_read",
        "vault_search",
        "vault_search_frontmatter",
    )


def test_v1_schema_and_owner_only_files_survive_reopen(state_paths):
    state = _state(state_paths)
    _, state_path, _ = state_paths

    assert state.schema_version == 1
    assert stat.S_IMODE(state_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert state.table_names() == {
        "access_token_capabilities",
        "access_tokens",
        "authorization_codes",
        "client_redirect_uris",
        "clients",
        "migration_metadata",
    }

    state.close()
    reopened = _state(state_paths)
    assert reopened.schema_version == 1
    reopened.close()


def test_simultaneous_initialization_is_idempotent(state_paths, monkeypatch):
    _, _, legacy_path = state_paths
    _write_legacy(
        legacy_path,
        {"client": {"client_secret": "secret", "redirect_uris": [REDIRECT]}},
    )
    original_unlink = Path.unlink

    def slow_legacy_unlink(path: Path, *args, **kwargs):
        if path == legacy_path:
            time.sleep(0.05)
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", slow_legacy_unlink)
    barrier = threading.Barrier(2)

    def open_once():
        barrier.wait()
        state = _state(state_paths)
        try:
            return state.schema_version, state.table_names(), len(state.list_clients())
        finally:
            state.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: open_once(), range(2)))

    assert results[0] == results[1]
    assert results[0][0] == 1
    assert results[0][2] == 1
    assert not legacy_path.exists()


def test_state_path_must_be_outside_vault(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir(mode=0o700)

    with pytest.raises(UnsafeStatePath, match="outside"):
        OAuthState(vault / "oauth.sqlite3", vault_path=vault)


@pytest.mark.parametrize("target", ["directory", "database", "wal", "shm"])
def test_symlinked_state_targets_are_rejected_before_open(tmp_path, target):
    vault = tmp_path / "vault"
    vault.mkdir(mode=0o700)
    state_dir = tmp_path / "state"
    state_path = state_dir / "oauth.sqlite3"
    planted = tmp_path / "planted"
    planted.write_text("sentinel")

    if target == "directory":
        state_dir.symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    else:
        state_dir.mkdir(mode=0o700)
        suffix = "" if target == "database" else f"-{target}"
        Path(f"{state_path}{suffix}").symlink_to(planted)

    with pytest.raises(UnsafeStatePath, match="symlink"):
        OAuthState(state_path, vault_path=vault)
    assert planted.read_text() == "sentinel"


def test_unsafe_mode_and_foreign_owner_are_rejected(state_paths, monkeypatch):
    state = _state(state_paths)
    _, state_path, _ = state_paths
    state.close()

    state_path.chmod(0o644)
    with pytest.raises(UnsafeStatePath, match="mode"):
        _state(state_paths)
    state_path.chmod(0o600)

    import obsidian_vault_mcp.oauth_state as oauth_state_module

    actual_uid = os.getuid()
    monkeypatch.setattr(oauth_state_module.os, "getuid", lambda: actual_uid + 1)
    with pytest.raises(UnsafeStatePath, match="owner"):
        _state(state_paths)


def test_registration_stores_only_domain_separated_verifiers(state_paths):
    state = _state(state_paths)
    first = state.register_client([REDIRECT])
    second = state.register_client(["https://second.example.test/callback"])
    _, state_path, _ = state_paths

    assert first.client.client_id != second.client.client_id
    assert first.client_secret != second.client_secret
    assert first.client_secret not in _db_text(state_path)
    assert second.client_secret not in _db_text(state_path)
    assert state.verify_client_secret(first.client.client_id, first.client_secret)
    assert not state.verify_client_secret(first.client.client_id, "wrong")
    assert state.client_redirect_uri_allowed(first.client.client_id, REDIRECT)
    state.close()


def test_token_wire_lookup_expiry_and_independent_revoke(state_paths):
    now = [1_000.0]
    state = _state(state_paths, now=now)
    first_id, _ = _register(state)
    second_id, _ = _register(state)

    first = state.issue_access_token(
        client_id=first_id,
        resource=RESOURCE,
    )
    second = state.issue_access_token(
        client_id=second_id,
        resource=RESOURCE,
    )

    assert first.access_token.startswith("v1.")
    assert first.access_token.count(".") == 2
    assert first.access_token != second.access_token
    assert state.lookup_access_token(first.access_token) == first.token
    assert state.lookup_access_token(first.access_token + "wrong") is None
    assert state.lookup_access_token("malformed") is None
    assert state.lookup_access_token("v1.unknown.secret") is None

    assert state.revoke_token(first.token.token_id)
    assert state.lookup_access_token(first.access_token) is None
    assert state.lookup_access_token(second.access_token) == second.token

    now[0] = second.token.expires_at
    assert state.lookup_access_token(second.access_token) is None
    state.close()


def test_authorization_code_expires_at_300_seconds_and_is_single_use(state_paths):
    now = [5_000.0]
    state = _state(state_paths, now=now)
    client_id, secret = _register(state)
    code = _issue_code(state, client_id)

    now[0] += 300
    with pytest.raises(InvalidGrant, match="expired"):
        _redeem(state, code, client_id, secret)

    now[0] = 6_000.0
    fresh = _issue_code(state, client_id)
    issued = _redeem(state, fresh, client_id, secret)
    assert issued.token.client_id == client_id
    with pytest.raises(InvalidGrant):
        _redeem(state, fresh, client_id, secret)
    state.close()


def test_code_exchange_checks_client_secret_redirect_pkce_and_resource(state_paths):
    state = _state(state_paths)
    client_id, secret = _register(state)

    checks = [
        ({"client_secret": "wrong"}, InvalidClient),
        ({"client_id": "wrong-client"}, InvalidClient),
        ({"redirect_uri": "https://wrong.example.test/cb"}, InvalidGrant),
        ({"code_verifier": "wrong"}, InvalidGrant),
        ({"resource": "https://wrong.example.test"}, InvalidTarget),
    ]
    for changes, error in checks:
        code = _issue_code(state, client_id)
        params = {
            "code": code,
            "client_id": client_id,
            "client_secret": secret,
            "redirect_uri": REDIRECT,
            "code_verifier": VERIFIER,
            "resource": RESOURCE,
        }
        params.update(changes)
        with pytest.raises(error):
            state.redeem_authorization_code(**params)
        assert state.authorization_code_active(code)

    state.close()


def test_simultaneous_redemption_issues_exactly_one_token(state_paths):
    state = _state(state_paths)
    client_id, secret = _register(state)
    code = _issue_code(state, client_id)
    state.close()
    barrier = threading.Barrier(2)

    def redeem_once():
        local = _state(state_paths)
        barrier.wait()
        try:
            return _redeem(local, code, client_id, secret).access_token
        except InvalidGrant:
            return None
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: redeem_once(), range(2)))

    assert sum(result is not None for result in results) == 1


def test_revoke_racing_redemption_cannot_leave_active_token(state_paths):
    state = _state(state_paths)
    client_id, secret = _register(state)
    code = _issue_code(state, client_id)
    state.close()
    barrier = threading.Barrier(2)

    def redeem_once():
        local = _state(state_paths)
        barrier.wait()
        try:
            return _redeem(local, code, client_id, secret).access_token
        except (InvalidClient, InvalidGrant):
            return None
        finally:
            local.close()

    def revoke_once():
        local = _state(state_paths)
        barrier.wait()
        try:
            assert local.revoke_client(client_id)
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        token_future = pool.submit(redeem_once)
        revoke_future = pool.submit(revoke_once)
        token = token_future.result()
        revoke_future.result()

    reopened = _state(state_paths)
    if token is not None:
        assert reopened.lookup_access_token(token) is None
    assert reopened.get_client(client_id).revoked_at is not None
    reopened.close()


def test_client_revoke_cascades_codes_and_tokens_across_reopen(state_paths):
    state = _state(state_paths)
    first_id, first_secret = _register(state)
    second_id, second_secret = _register(state)
    first_code = _issue_code(state, first_id)
    first_token = _redeem(state, first_code, first_id, first_secret)
    pending = _issue_code(state, first_id)
    second_code = _issue_code(state, second_id)
    second_token = _redeem(state, second_code, second_id, second_secret)

    assert state.revoke_client(first_id)
    state.close()
    reopened = _state(state_paths)

    assert reopened.lookup_access_token(first_token.access_token) is None
    with pytest.raises((InvalidClient, InvalidGrant)):
        _redeem(reopened, pending, first_id, first_secret)
    assert reopened.lookup_access_token(second_token.access_token) == second_token.token
    reopened.close()


def test_legacy_migration_is_allowlisted_one_way_and_secret_free(state_paths):
    _, state_path, legacy_path = state_paths
    records = {
        "approved-client": {
            "client_secret": "approved-secret-marker",
            "redirect_uris": ["https://approved.example.test/cb"],
            "created_at": 1.0,
        },
        "pending-client": {
            "client_secret": "pending-secret-marker",
            "redirect_uris": ["https://pending.example.test/cb"],
            "created_at": 2.0,
        },
    }
    _write_legacy(legacy_path, records)

    state = _state(state_paths, approved=frozenset({"approved-client"}))

    assert not legacy_path.exists()
    assert state.get_client("approved-client").policy == LEGACY_FULL
    assert state.get_client("pending-client").policy == REAUTHORIZATION_REQUIRED
    assert not state.can_issue_authorization_code("pending-client")
    with pytest.raises(InvalidClient):
        state.issue_authorization_code(
            client_id="pending-client",
            redirect_uri="https://pending.example.test/cb",
            code_challenge=CHALLENGE,
            resource=RESOURCE,
        )
    state.issue_authorization_code(
        client_id="pending-client",
        redirect_uri="https://pending.example.test/cb",
        code_challenge=CHALLENGE,
        resource=RESOURCE,
        fresh_reauthorization=True,
    )
    transitioned = state.get_client("pending-client")
    assert transitioned is not None
    assert transitioned.policy == VAULT_READONLY_V1
    assert transitioned.capabilities == VAULT_READONLY_CAPABILITIES
    assert "approved-secret-marker" not in _db_text(state_path)
    assert "pending-secret-marker" not in _db_text(state_path)
    state.close()


@pytest.mark.parametrize(
    "records,approved",
    [
        ({"client": {"redirect_uris": [REDIRECT]}}, frozenset()),
        ({"client": {"client_secret": "s", "redirect_uris": "bad"}}, frozenset()),
        (
            {
                "a": {"client_secret": "a", "redirect_uris": [REDIRECT]},
                "b": {"client_secret": "b", "redirect_uris": [REDIRECT]},
            },
            frozenset(),
        ),
        (
            {"present": {"client_secret": "s", "redirect_uris": [REDIRECT]}},
            frozenset({"absent"}),
        ),
    ],
)
def test_invalid_legacy_import_is_atomic(state_paths, records, approved):
    _, state_path, legacy_path = state_paths
    _write_legacy(legacy_path, records)

    with pytest.raises(ValueError):
        _state(state_paths, approved=approved)

    assert legacy_path.exists()
    if state_path.exists():
        with sqlite3.connect(state_path) as connection:
            assert connection.execute("SELECT count(*) FROM clients").fetchone()[0] == 0


def test_unsafe_legacy_permissions_abort_import(state_paths):
    _, state_path, legacy_path = state_paths
    _write_legacy(
        legacy_path,
        {"client": {"client_secret": "secret", "redirect_uris": [REDIRECT]}},
    )
    legacy_path.chmod(0o644)

    with pytest.raises(UnsafeStatePath, match="mode"):
        _state(state_paths)
    assert legacy_path.exists()
    if state_path.exists():
        with sqlite3.connect(state_path) as connection:
            assert connection.execute("SELECT count(*) FROM clients").fetchone()[0] == 0


def test_completed_migration_never_reimports_changed_source(state_paths):
    _, _, legacy_path = state_paths
    _write_legacy(
        legacy_path,
        {"first": {"client_secret": "one", "redirect_uris": [REDIRECT]}},
    )
    state = _state(state_paths)
    state.close()

    _write_legacy(
        legacy_path,
        {"second": {"client_secret": "two", "redirect_uris": [REDIRECT]}},
    )
    reopened = _state(state_paths)
    assert reopened.get_client("first") is not None
    assert reopened.get_client("second") is None
    assert legacy_path.exists()
    reopened.close()


def test_unlink_failure_blocks_startup_then_retries_without_reimport(
    state_paths, monkeypatch
):
    _, _, legacy_path = state_paths
    _write_legacy(
        legacy_path,
        {"client": {"client_secret": "secret", "redirect_uris": [REDIRECT]}},
    )
    original_unlink = Path.unlink

    def fail_legacy_unlink(path: Path, *args, **kwargs):
        if path == legacy_path:
            raise OSError("synthetic unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_legacy_unlink)
    with pytest.raises(OSError, match="synthetic unlink failure"):
        _state(state_paths)
    assert legacy_path.exists()

    monkeypatch.setattr(Path, "unlink", original_unlink)
    reopened = _state(state_paths)
    assert reopened.get_client("client") is not None
    assert len(reopened.list_clients()) == 1
    assert not legacy_path.exists()
    reopened.close()


def test_migration_cleanup_accepts_source_removed_by_concurrent_initializer(
    state_paths, monkeypatch
):
    _, _, legacy_path = state_paths
    _write_legacy(
        legacy_path,
        {"client": {"client_secret": "secret", "redirect_uris": [REDIRECT]}},
    )
    original_unlink = Path.unlink

    def concurrent_unlink(path: Path, *args, **kwargs):
        if path == legacy_path:
            original_unlink(path, *args, **kwargs)
            raise FileNotFoundError(path)
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", concurrent_unlink)
    state = _state(state_paths)
    assert state.get_client("client") is not None
    assert not legacy_path.exists()
    state.close()


def test_migration_unlink_is_durable_before_cleanup_marker_clears(
    state_paths, monkeypatch
):
    _, state_path, legacy_path = state_paths
    _write_legacy(
        legacy_path,
        {"client": {"client_secret": "secret", "redirect_uris": [REDIRECT]}},
    )
    original_fsync = os.fsync

    def fail_directory_fsync(file_descriptor: int):
        metadata = os.fstat(file_descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            raise OSError("synthetic directory fsync failure")
        return original_fsync(file_descriptor)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(OSError, match="synthetic directory fsync failure"):
        _state(state_paths)
    assert not legacy_path.exists()
    with sqlite3.connect(state_path) as connection:
        assert (
            connection.execute(
                "SELECT cleanup_pending FROM migration_metadata "
                "WHERE name = 'legacy_clients_json_v1'"
            ).fetchone()[0]
            == 1
        )

    monkeypatch.setattr(os, "fsync", original_fsync)
    reopened = _state(state_paths)
    with sqlite3.connect(state_path) as connection:
        assert (
            connection.execute(
                "SELECT cleanup_pending FROM migration_metadata "
                "WHERE name = 'legacy_clients_json_v1'"
            ).fetchone()[0]
            == 0
        )
    reopened.close()


def test_static_client_revoke_survives_restart(state_paths):
    state = _state(state_paths)
    client = state.ensure_static_client(
        "static-client",
        [REDIRECT],
        policy=LEGACY_FULL,
        capabilities=(),
    )
    assert client.is_static
    assert state.verify_client_secret("static-client", STATIC_SECRET)
    assert state.revoke_client("static-client")
    state.close()

    reopened = _state(state_paths)
    assert reopened.get_client("static-client").revoked_at is not None
    assert not reopened.verify_client_secret("static-client", STATIC_SECRET)
    with pytest.raises(InvalidClient):
        reopened.issue_access_token(
            client_id="static-client",
            resource=RESOURCE,
        )
    reopened.ensure_static_client(
        "static-client",
        [REDIRECT],
        policy=LEGACY_FULL,
        capabilities=(),
    )
    assert reopened.get_client("static-client").revoked_at is not None
    reopened.close()


def test_backup_rejects_unsafe_target_and_produces_reopenable_copy(state_paths):
    state = _state(state_paths)
    _register(state)
    vault, _, _ = state_paths
    backup = state.path.parent.parent / "backups" / "oauth.sqlite3"
    with pytest.raises(UnsafeStatePath, match="live OAuth state"):
        state.backup(state.path)

    copied = state.backup(backup)
    assert copied == backup
    assert stat.S_IMODE(backup.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    with sqlite3.connect(backup) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM clients").fetchone()[0] == 1

    planted = backup.parent / "planted"
    planted.write_text("sentinel")
    unsafe = backup.parent / "unsafe.sqlite3"
    unsafe.symlink_to(planted)
    with pytest.raises(UnsafeStatePath, match="symlink"):
        state.backup(unsafe)
    assert planted.read_text() == "sentinel"

    sidecar_target = backup.parent / "sidecar.sqlite3"
    unsafe_sidecar = Path(f"{sidecar_target}-wal")
    unsafe_sidecar.symlink_to(planted)
    with pytest.raises(UnsafeStatePath, match="sidecar"):
        state.backup(sidecar_target)
    assert planted.read_text() == "sentinel"

    with pytest.raises(UnsafeStatePath, match="outside"):
        state.backup(vault / "backup.sqlite3")
    state.close()
