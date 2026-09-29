"""Tests of the durable OAuth state."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from obsidian_vault_mcp.oauth_state import (
    InvalidClient,
    InvalidGrant,
    InvalidTarget,
    OAuthState,
    OAuthStateError,
)

RESOURCE = "https://vault.example.test"
REDIRECT = "https://client.example.test/callback"


@pytest.fixture
def state_path(tmp_path: Path) -> Path:
    """Path of the state file."""
    return tmp_path / "state" / "oauth_state.sqlite3"


def _open(state_path: Path, *, now: list[float] | None = None) -> OAuthState:
    """Open the store with an optional clock."""
    clock = (lambda: now[0]) if now is not None else None
    return OAuthState(state_path, clock=clock)


def _db_bytes(state_path: Path) -> bytes:
    """Everything SQLite has on disk for this database, sidecars included."""
    chunks = [state_path.read_bytes()]
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{state_path}{suffix}")
        if sidecar.exists():
            chunks.append(sidecar.read_bytes())
    return b"".join(chunks)


# --- Clients -----------------------------------------------------------------------------


def test_registered_client_survives_reopen(state_path):
    state = _open(state_path, now=[1_000.0])
    registered = state.register_client([REDIRECT], client_name="Claude")
    state.close()

    reopened = _open(state_path)
    client = reopened.get_client(registered.client.client_id)
    reopened.close()

    assert client is not None
    assert client.redirect_uris == (REDIRECT,)
    assert client.client_name == "Claude"
    assert client.created_at == 1_000.0
    assert client.revoked_at is None
    assert client.is_static is False


def test_client_secret_is_never_written_to_disk(state_path):
    state = _open(state_path)
    registered = state.register_client([REDIRECT])

    assert registered.client_secret.encode() not in _db_bytes(state_path)
    state.close()
    assert registered.client_secret.encode() not in _db_bytes(state_path)


def test_client_secret_verifies_only_for_its_own_client(state_path):
    state = _open(state_path)
    first = state.register_client([REDIRECT])
    second = state.register_client([REDIRECT])

    assert state.verify_client_secret(first.client.client_id, first.client_secret)
    assert not state.verify_client_secret(first.client.client_id, second.client_secret)
    assert not state.verify_client_secret(first.client.client_id, "")
    assert not state.verify_client_secret("vault-mcp-unknown", first.client_secret)
    state.close()


def test_list_clients_returns_every_client_oldest_first(state_path):
    # Ids are chosen so that neither id order nor reverse creation order gives this result.
    now = [1_000.0]
    state = _open(state_path, now=now)
    state.ensure_static_client("zzz-first")
    now[0] = 2_000.0
    middle = state.register_client([REDIRECT]).client.client_id
    now[0] = 3_000.0
    state.ensure_static_client("aaa-last")

    listed = state.list_clients()
    state.close()

    assert [client.client_id for client in listed] == ["zzz-first", middle, "aaa-last"]


def test_redirect_repeated_in_one_registration_is_stored_once(state_path):
    state = _open(state_path)

    registered = state.register_client([REDIRECT, REDIRECT])

    assert registered.client.redirect_uris == (REDIRECT,)
    assert state.client_redirect_uri_allowed(registered.client.client_id, REDIRECT)
    state.close()


def test_state_written_by_a_newer_version_is_refused(state_path):
    _open(state_path).close()
    connection = sqlite3.connect(state_path)
    connection.execute("PRAGMA user_version = 2")
    connection.close()

    with pytest.raises(OAuthStateError, match="schema version 2"):
        _open(state_path)


# --- Access tokens -----------------------------------------------------------------------


def test_issuing_a_pair_records_when_the_client_last_authorized(state_path):
    now = [1_000.0]
    state = _open(state_path, now=now)
    client_id = state.register_client([REDIRECT]).client.client_id
    assert state.get_client(client_id).last_authorized_at is None

    now[0] = 5_000.0
    state.issue_token_pair(client_id=client_id, resource=RESOURCE)

    assert state.get_client(client_id).last_authorized_at == 5_000.0
    state.close()


def test_tokens_are_never_written_to_disk(state_path):
    state = _open(state_path)
    client_id = state.register_client([REDIRECT]).client.client_id
    issued = state.issue_token_pair(client_id=client_id, resource=RESOURCE)
    state.close()

    on_disk = _db_bytes(state_path)
    assert issued.access_token.split(".")[2].encode() not in on_disk
    assert issued.refresh_token.split(".")[2].encode() not in on_disk


def test_access_token_is_found_by_its_exact_value_only(state_path):
    state = _open(state_path)
    client_id = state.register_client([REDIRECT]).client.client_id
    issued = state.issue_token_pair(client_id=client_id, resource=RESOURCE)

    assert state.lookup_access_token(issued.access_token) == issued.token
    assert state.lookup_access_token(issued.access_token + "x") is None
    assert state.lookup_access_token(issued.refresh_token) is None
    assert state.lookup_access_token("v1.unknown.secret") is None
    assert state.lookup_access_token("not-a-token") is None
    state.close()


def test_access_token_lives_one_day(state_path):
    now = [1_000.0]
    state = _open(state_path, now=now)
    client_id = state.register_client([REDIRECT]).client.client_id
    issued = state.issue_token_pair(client_id=client_id, resource=RESOURCE)

    now[0] = 1_000.0 + 86_400 - 1
    assert state.lookup_access_token(issued.access_token) == issued.token
    now[0] = 1_000.0 + 86_400
    assert state.lookup_access_token(issued.access_token) is None
    state.close()


@pytest.mark.parametrize("issue", ["issue_token_pair", "issue_access_token"])
def test_unknown_client_gets_no_token(state_path, issue):
    state = _open(state_path)

    with pytest.raises(InvalidClient):
        getattr(state, issue)(client_id="vault-mcp-unknown", resource=RESOURCE)
    state.close()


# --- Refresh tokens ----------------------------------------------------------------------


def _pair(state: OAuthState):
    """A client with a token pair."""
    client_id = state.register_client([REDIRECT]).client.client_id
    return client_id, state.issue_token_pair(client_id=client_id, resource=RESOURCE)


def _refresh(state: OAuthState, refresh_token: str, client_id: str, resource: str = RESOURCE):
    """Redeem a refresh token, accepting only the given resource."""
    return state.redeem_refresh_token(
        refresh_token=refresh_token, client_id=client_id,
        resource_ok=lambda stored: stored == resource,
    )


def test_refresh_works_after_the_access_token_expired(state_path):
    now = [1_000.0]
    state = _open(state_path, now=now)
    client_id, issued = _pair(state)

    now[0] = 1_000.0 + 86_400 + 1
    assert state.lookup_access_token(issued.access_token) is None
    rotated = _refresh(state, issued.refresh_token, client_id)

    assert state.lookup_access_token(rotated.access_token) == rotated.token
    state.close()


def test_token_pair_survives_reopen(state_path):
    state = _open(state_path)
    client_id, issued = _pair(state)
    state.close()

    reopened = _open(state_path)
    assert reopened.lookup_access_token(issued.access_token) == issued.token
    rotated = _refresh(reopened, issued.refresh_token, client_id)
    assert reopened.lookup_access_token(rotated.access_token) == rotated.token
    reopened.close()


def test_refresh_token_lives_thirty_days(state_path):
    now = [1_000.0]
    state = _open(state_path, now=now)
    client_id, issued = _pair(state)

    now[0] = 1_000.0 + 30 * 86_400
    with pytest.raises(InvalidGrant):
        _refresh(state, issued.refresh_token, client_id)

    now[0] = 1_000.0 + 30 * 86_400 - 1
    rotated = _refresh(state, issued.refresh_token, client_id)
    assert state.lookup_access_token(rotated.access_token) == rotated.token
    state.close()


def test_refresh_for_another_resource_is_refused_and_not_spent(state_path):
    state = _open(state_path)
    client_id, issued = _pair(state)

    with pytest.raises(InvalidTarget):
        _refresh(state, issued.refresh_token, client_id, resource="https://other.example.test")

    rotated = _refresh(state, issued.refresh_token, client_id)
    assert rotated.token.resource == RESOURCE
    state.close()


def test_refresh_token_works_only_for_the_client_it_was_issued_to(state_path):
    state = _open(state_path)
    client_id, issued = _pair(state)
    other_id = state.register_client([REDIRECT]).client.client_id

    with pytest.raises(InvalidGrant):
        _refresh(state, issued.refresh_token, other_id)

    rotated = _refresh(state, issued.refresh_token, client_id)
    assert rotated.token.client_id == client_id
    state.close()


@pytest.mark.parametrize(
    "forged",
    ["not-a-token", "r1.unknown.secret", "v1.aaa.bbb", "r1..secret", ""],
)
def test_forged_refresh_token_is_refused(state_path, forged):
    state = _open(state_path)
    client_id, _issued = _pair(state)

    with pytest.raises(InvalidGrant):
        _refresh(state, forged, client_id)
    state.close()


def test_refresh_token_with_a_wrong_secret_is_refused(state_path):
    state = _open(state_path)
    client_id, issued = _pair(state)

    with pytest.raises(InvalidGrant):
        _refresh(state, issued.refresh_token + "x", client_id)

    rotated = _refresh(state, issued.refresh_token, client_id)
    assert state.lookup_access_token(rotated.access_token) == rotated.token
    state.close()


def test_two_simultaneous_refreshes_issue_exactly_one_pair(state_path):
    state = _open(state_path)
    client_id, issued = _pair(state)
    state.close()
    barrier = threading.Barrier(2)

    def refresh_once(_):
        """Refresh once from its own connection."""
        local = _open(state_path)
        barrier.wait()
        try:
            return _refresh(local, issued.refresh_token, client_id).access_token
        except InvalidGrant:
            return None
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(refresh_once, range(2)))

    assert sum(result is not None for result in results) == 1


def test_refresh_records_when_the_client_last_authorized(state_path):
    now = [1_000.0]
    state = _open(state_path, now=now)
    client_id, issued = _pair(state)

    now[0] = 7_000.0
    _refresh(state, issued.refresh_token, client_id)

    assert state.get_client(client_id).last_authorized_at == 7_000.0
    state.close()


# --- Expiry while waiting for the store --------------------------------------------------


class _Clock:
    """A clock the test moves by hand."""

    def __init__(self, now: float) -> None:
        """Start at the given moment."""
        self.now = now

    def __call__(self) -> float:
        """The current moment."""
        return self.now


class _AnnouncingLock:
    """The lock of the store, reporting when a caller starts to wait for it."""

    def __init__(self, lock) -> None:
        """Wrap the real lock."""
        self._lock = lock
        self.waiting = threading.Event()

    def __enter__(self):
        """Announce the wait, then take the lock."""
        self.waiting.set()
        return self._lock.__enter__()

    def __exit__(self, *exc_info):
        """Release the lock."""
        return self._lock.__exit__(*exc_info)


def _call_after_waiting_for_the_store(state: OAuthState, clock: _Clock, later: float, call):
    """Run call while the store is busy and move the clock to later during the wait."""
    outcome = {}
    real_lock = state._lock
    state._lock = _AnnouncingLock(real_lock)

    def run():
        """Make the call and keep its outcome."""
        try:
            outcome["result"] = call()
        except OAuthStateError as exc:
            outcome["error"] = type(exc)

    with real_lock:
        waiting = threading.Thread(target=run)
        waiting.start()
        # Moved only once the call waits for the store, so code that read the clock
        # before the wait has the earlier moment however late the thread started.
        assert state._lock.waiting.wait(5), "the call never waited for the store"
        clock.now = later
    waiting.join(5)
    assert not waiting.is_alive()
    state._lock = real_lock
    return outcome


def test_access_token_that_expired_during_the_wait_is_refused(state_path):
    clock = _Clock(1_000.0)
    state = OAuthState(state_path, clock=clock)
    client_id = state.register_client([REDIRECT]).client.client_id
    issued = state.issue_token_pair(client_id=client_id, resource=RESOURCE)

    clock.now = issued.token.expires_at - 1
    outcome = _call_after_waiting_for_the_store(
        state,
        clock,
        issued.token.expires_at + 1,
        lambda: state.lookup_access_token(issued.access_token),
    )

    assert outcome == {"result": None}
    state.close()


def test_refresh_token_that_expired_during_the_wait_is_refused(state_path):
    clock = _Clock(1_000.0)
    state = OAuthState(state_path, clock=clock)
    client_id, issued = _pair(state)
    expires_at = 1_000.0 + 30 * 86_400

    clock.now = expires_at - 1
    outcome = _call_after_waiting_for_the_store(
        state,
        clock,
        expires_at + 1,
        lambda: _refresh(state, issued.refresh_token, client_id),
    )

    assert outcome == {"error": InvalidGrant}
    clock.now = 1_000.0
    assert state.lookup_access_token(issued.access_token) == issued.token
    state.close()


# --- Revocation --------------------------------------------------------------------------


def test_revoking_a_client_kills_everything_it_holds(state_path):
    now = [1_000.0]
    state = _open(state_path, now=now)
    registered = state.register_client([REDIRECT])
    client_id = registered.client.client_id
    issued = state.issue_token_pair(client_id=client_id, resource=RESOURCE)

    now[0] = 2_000.0
    assert state.revoke_client(client_id) is True

    assert state.get_client(client_id).revoked_at == 2_000.0
    assert state.lookup_access_token(issued.access_token) is None
    assert not state.verify_client_secret(client_id, registered.client_secret)
    assert not state.client_redirect_uri_allowed(client_id, REDIRECT)
    with pytest.raises(InvalidClient):
        _refresh(state, issued.refresh_token, client_id)
    with pytest.raises(InvalidClient):
        state.issue_token_pair(client_id=client_id, resource=RESOURCE)
    with pytest.raises(InvalidClient):
        state.issue_access_token(client_id=client_id, resource=RESOURCE)
    state.close()


def test_revoke_racing_a_refresh_leaves_no_usable_token(state_path):
    state = _open(state_path)
    client_id, issued = _pair(state)
    state.close()
    barrier = threading.Barrier(2)

    def refresh_once():
        """Refresh once from its own connection."""
        local = _open(state_path)
        barrier.wait()
        try:
            return _refresh(local, issued.refresh_token, client_id).access_token
        except (InvalidClient, InvalidGrant):
            return None
        finally:
            local.close()

    def revoke_once():
        """Revoke once from its own connection."""
        local = _open(state_path)
        barrier.wait()
        try:
            return local.revoke_client(client_id)
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        token_future = pool.submit(refresh_once)
        revoke_future = pool.submit(revoke_once)
        token = token_future.result()
        assert revoke_future.result() is True

    reopened = _open(state_path)
    if token is not None:
        assert reopened.lookup_access_token(token) is None
    assert reopened.lookup_access_token(issued.access_token) is None
    reopened.close()


# --- The operator-configured client ------------------------------------------------------


def test_configured_client_is_created_without_a_stored_secret(state_path):
    state = _open(state_path)

    client = state.ensure_static_client("operator-client")

    assert client.is_static is True
    assert client.redirect_uris == ()
    assert not state.verify_client_secret("operator-client", "any-secret")
    issued = state.issue_access_token(client_id="operator-client", resource=RESOURCE)
    assert state.lookup_access_token(issued.access_token) == issued.token
    state.close()


def test_configured_client_id_cannot_take_over_a_registered_client(state_path):
    state = _open(state_path)
    registered = state.register_client([REDIRECT])

    with pytest.raises(ValueError, match="already registered"):
        state.ensure_static_client(registered.client.client_id)

    assert state.get_client(registered.client.client_id).is_static is False
    assert state.verify_client_secret(
        registered.client.client_id, registered.client_secret
    )
    state.close()


# --- File permissions --------------------------------------------------------------------

posix_modes = pytest.mark.skipif(
    os.name == "nt", reason="file modes are meaningless on Windows"
)


def _mode(path: Path) -> int:
    """Permission bits of a path."""
    return path.stat().st_mode & 0o777


def _state_files(state_path: Path) -> list[Path]:
    """Database file and its sidecars."""
    return [state_path, Path(f"{state_path}-wal"), Path(f"{state_path}-shm")]


@posix_modes
def test_existing_database_and_its_sidecars_are_tightened(state_path):
    running = _open(state_path)
    registered = running.register_client([REDIRECT])
    for path in _state_files(state_path):
        path.chmod(0o644)

    state = _open(state_path)

    modes = {path.name: _mode(path) for path in _state_files(state_path)}
    assert modes == {path.name: 0o600 for path in _state_files(state_path)}
    assert state.get_client(registered.client.client_id) is not None
    state.close()
    running.close()


@posix_modes
def test_database_that_vanishes_while_opening_is_still_owner_only(state_path, monkeypatch):
    state_path.parent.mkdir(parents=True)
    state_path.write_bytes(b"")
    state_path.chmod(0o644)
    real_chmod = os.chmod
    vanished = []

    def chmod_a_file_that_just_vanished(path, mode, *args, **kwargs):
        """Remove the database once, then chmod."""
        if str(path) == str(state_path) and not vanished:
            vanished.append(path)
            state_path.unlink()
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", chmod_a_file_that_just_vanished)

    state = _open(state_path)
    state.register_client([REDIRECT])

    modes = {path.name: _mode(path) for path in _state_files(state_path)}
    state.close()
    assert len(vanished) == 1
    assert modes == {path.name: 0o600 for path in _state_files(state_path)}


def test_store_reopens_after_sqlite_removed_its_sidecars(state_path):
    state = _open(state_path)
    registered = state.register_client([REDIRECT])
    state.close()
    for sidecar in _state_files(state_path)[1:]:
        sidecar.unlink(missing_ok=True)

    reopened = _open(state_path)

    assert reopened.get_client(registered.client.client_id) is not None
    reopened.close()


# --- Import of the JSON registry ---------------------------------------------------------

SHARED_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
PRIVATE = "registry-value-that-must-stay-out-of-the-log"
PRIVATE_URL = "https://callback.example.test/must-stay-out-of-the-log"


@pytest.fixture
def legacy_path(state_path: Path) -> Path:
    """Path of the JSON registry."""
    return state_path.parent / "oauth_clients.json"


def _write_registry(legacy_path: Path, registry: object) -> None:
    """Write the JSON registry."""
    legacy_path.parent.mkdir(parents=True, exist_ok=True)
    legacy_path.write_text(json.dumps(registry))


def _entry(secret: str, redirect_uris: list[str], created_at: float = 500.0) -> dict:
    """A registry entry as main wrote it."""
    return {"client_secret": secret, "redirect_uris": redirect_uris, "created_at": created_at}


def _imported_ids(state: OAuthState) -> set[str]:
    """Ids of the stored clients."""
    return {client.client_id for client in state.list_clients()}


def test_import_reads_a_registry_as_main_wrote_it(state_path, legacy_path):
    _write_registry(
        legacy_path,
        {
            "vault-mcp-one": _entry("secret-one", [SHARED_CALLBACK], created_at=100.0),
            "vault-mcp-two": _entry("secret-two", [SHARED_CALLBACK], created_at=200.0),
            "vault-mcp-three": _entry("secret-three", [SHARED_CALLBACK, SHARED_CALLBACK]),
            "vault-mcp-empty": _entry("secret-empty", []),
        },
    )
    before = legacy_path.read_bytes()

    state = OAuthState(state_path, legacy_path=legacy_path, clock=lambda: 9_000.0)

    assert _imported_ids(state) == {
        "vault-mcp-one",
        "vault-mcp-two",
        "vault-mcp-three",
        "vault-mcp-empty",
    }
    for name in ("one", "two", "three"):
        assert state.verify_client_secret(f"vault-mcp-{name}", f"secret-{name}")
        assert state.client_redirect_uri_allowed(f"vault-mcp-{name}", SHARED_CALLBACK)
    assert state.get_client("vault-mcp-three").redirect_uris == (SHARED_CALLBACK,)
    assert state.verify_client_secret("vault-mcp-empty", "secret-empty")
    assert state.get_client("vault-mcp-empty").redirect_uris == ()
    assert state.get_client("vault-mcp-one").created_at == 100.0
    assert state.get_client("vault-mcp-one").is_static is False
    assert b"secret-one" not in _db_bytes(state_path)
    state.close()
    assert legacy_path.read_bytes() == before


def test_import_dates_a_client_itself_when_the_registry_has_no_usable_date(
    state_path, legacy_path
):
    _write_registry(
        legacy_path,
        {
            "vault-mcp-flag": {"client_secret": "s", "redirect_uris": [], "created_at": True},
            "vault-mcp-text": {"client_secret": "s", "redirect_uris": [], "created_at": "now"},
            "vault-mcp-none": {"client_secret": "s", "redirect_uris": []},
        },
    )

    state = OAuthState(state_path, legacy_path=legacy_path, clock=lambda: 9_000.0)

    dates = {client.client_id: client.created_at for client in state.list_clients()}
    assert dates == {
        "vault-mcp-flag": 9_000.0,
        "vault-mcp-text": 9_000.0,
        "vault-mcp-none": 9_000.0,
    }
    state.close()


@pytest.mark.parametrize(
    "created_at",
    [float("nan"), float("inf"), float("-inf"), 10**400],
    ids=["nan", "inf", "minus-inf", "too-large"],
)
def test_import_dates_a_client_itself_when_the_date_is_not_a_real_moment(
    state_path, legacy_path, created_at
):
    _write_registry(
        legacy_path,
        {
            "vault-mcp-good": _entry("secret-good", [REDIRECT], created_at=100.0),
            "vault-mcp-odd": _entry("secret-odd", [REDIRECT], created_at=created_at),
        },
    )

    state = OAuthState(state_path, legacy_path=legacy_path, clock=lambda: 9_000.0)

    dates = {client.client_id: client.created_at for client in state.list_clients()}
    assert dates == {"vault-mcp-good": 100.0, "vault-mcp-odd": 9_000.0}
    assert state.verify_client_secret("vault-mcp-odd", "secret-odd")
    state.close()


LONE_SURROGATE = "\ud800"


@pytest.mark.parametrize(
    ("client_id", "entry"),
    [
        ("vault-mcp-odd", _entry("secret" + LONE_SURROGATE, [REDIRECT])),
        ("vault-mcp-odd", _entry("secret-odd", [REDIRECT, REDIRECT + LONE_SURROGATE])),
        ("vault-mcp-odd" + LONE_SURROGATE, _entry("secret-odd", [REDIRECT])),
    ],
    ids=["secret", "redirect", "client-id"],
)
def test_import_skips_an_entry_sqlite_cannot_store(
    state_path, legacy_path, client_id, entry, caplog
):
    _write_registry(
        legacy_path,
        {
            "vault-mcp-before": _entry("secret-before", [REDIRECT]),
            client_id: entry,
            "vault-mcp-after": _entry("secret-after", [REDIRECT]),
        },
    )

    with caplog.at_level("WARNING", logger="obsidian_vault_mcp.oauth_state"):
        state = OAuthState(state_path, legacy_path=legacy_path)

    assert _imported_ids(state) == {"vault-mcp-before", "vault-mcp-after"}
    assert state.verify_client_secret("vault-mcp-before", "secret-before")
    assert state.verify_client_secret("vault-mcp-after", "secret-after")
    assert state.client_redirect_uri_allowed("vault-mcp-after", REDIRECT)
    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == 1
    assert "skipped 1 entries" in messages[0]
    state.close()


def test_missing_registry_is_not_worth_a_warning(state_path, legacy_path, caplog):
    with caplog.at_level("WARNING", logger="obsidian_vault_mcp.oauth_state"):
        state = OAuthState(state_path, legacy_path=legacy_path)

    assert state.list_clients() == ()
    assert caplog.records == []
    state.close()


def test_import_retries_when_legacy_file_appears(state_path, legacy_path):
    OAuthState(state_path, legacy_path=legacy_path).close()

    _write_registry(legacy_path, {"vault-mcp-one": _entry("secret-one", [REDIRECT])})
    state = OAuthState(state_path, legacy_path=legacy_path)
    assert _imported_ids(state) == {"vault-mcp-one"}
    state.close()

    _write_registry(
        legacy_path,
        {
            "vault-mcp-one": _entry("secret-one", [REDIRECT]),
            "vault-mcp-late": _entry("secret-late", [REDIRECT]),
        },
    )
    reopened = OAuthState(state_path, legacy_path=legacy_path)
    assert _imported_ids(reopened) == {"vault-mcp-one", "vault-mcp-late"}
    assert reopened.verify_client_secret("vault-mcp-late", "secret-late")
    reopened.close()


def test_import_skips_malformed_entry(state_path, legacy_path, caplog):
    _write_registry(
        legacy_path,
        {
            "record-is-not-an-object": PRIVATE,
            "secret-is-missing": {"redirect_uris": [PRIVATE_URL]},
            "secret-is-not-a-string": {"client_secret": 42, "redirect_uris": [PRIVATE_URL]},
            "redirects-are-missing": {"client_secret": PRIVATE},
            "redirects-are-not-a-list": {"client_secret": PRIVATE, "redirect_uris": PRIVATE_URL},
            "redirect-is-not-a-string": {"client_secret": PRIVATE, "redirect_uris": [PRIVATE_URL, 7]},
            "vault-mcp-good": _entry("secret-good", [REDIRECT]),
        },
    )

    with caplog.at_level("WARNING", logger="obsidian_vault_mcp.oauth_state"):
        state = OAuthState(state_path, legacy_path=legacy_path)

    assert _imported_ids(state) == {"vault-mcp-good"}
    assert state.verify_client_secret("vault-mcp-good", "secret-good")
    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == 1
    assert "skipped 6 entries" in messages[0]
    assert PRIVATE not in messages[0]
    assert PRIVATE_URL not in messages[0]
    assert "secret-good" not in messages[0]
    state.close()


@pytest.mark.parametrize(
    "content",
    ['{"' + PRIVATE, '["' + PRIVATE + '"]', '"' + PRIVATE + '"', ""],
    ids=["broken-json", "list", "string", "empty"],
)
def test_import_tolerates_a_registry_it_cannot_read(state_path, legacy_path, content, caplog):
    legacy_path.parent.mkdir(parents=True)
    legacy_path.write_text(content)

    with caplog.at_level("WARNING", logger="obsidian_vault_mcp.oauth_state"):
        state = OAuthState(state_path, legacy_path=legacy_path)

    assert state.list_clients() == ()
    assert len(caplog.records) == 1
    assert PRIVATE not in caplog.records[0].getMessage()
    registered = state.register_client([REDIRECT])
    assert state.get_client(registered.client.client_id) is not None
    state.close()
    assert legacy_path.read_text() == content


def test_import_does_not_overwrite_existing_client(state_path, legacy_path):
    _write_registry(
        legacy_path,
        {
            "vault-mcp-active": _entry("old-secret", [REDIRECT]),
            "vault-mcp-revoked": _entry("revoked-secret", [REDIRECT]),
        },
    )
    state = OAuthState(state_path, legacy_path=legacy_path)
    state.revoke_client("vault-mcp-revoked")
    state.close()

    other = "https://other.example.test/callback"
    _write_registry(
        legacy_path,
        {
            "vault-mcp-active": _entry("new-secret", [other]),
            "vault-mcp-revoked": _entry("revoked-secret", [REDIRECT]),
        },
    )
    reopened = OAuthState(state_path, legacy_path=legacy_path)

    assert reopened.verify_client_secret("vault-mcp-active", "old-secret")
    assert not reopened.verify_client_secret("vault-mcp-active", "new-secret")
    assert reopened.get_client("vault-mcp-active").redirect_uris == (REDIRECT,)
    assert reopened.get_client("vault-mcp-revoked").revoked_at is not None
    assert not reopened.client_redirect_uri_allowed("vault-mcp-revoked", REDIRECT)
    reopened.close()
