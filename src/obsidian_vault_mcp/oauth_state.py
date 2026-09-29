"""Durable OAuth state: registered clients and the tokens issued to them.

One SQLite file holds everything. Client secrets are stored only as hashes, so a copy
of the file does not hand out a usable credential.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import math
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60
REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    secret_verifier BLOB,
    is_static INTEGER NOT NULL CHECK (is_static IN (0, 1)),
    client_name TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_authorized_at REAL,
    revoked_at REAL
);
CREATE TABLE IF NOT EXISTS client_redirect_uris (
    client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    PRIMARY KEY (client_id, redirect_uri)
);
CREATE TABLE IF NOT EXISTS access_tokens (
    token_id TEXT PRIMARY KEY,
    secret_verifier BLOB NOT NULL,
    client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_id TEXT PRIMARY KEY,
    secret_verifier BLOB NOT NULL,
    client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    access_token_id TEXT NOT NULL REFERENCES access_tokens(token_id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    consumed_at REAL
);
"""


# --- Errors ------------------------------------------------------------------------------


class OAuthStateError(RuntimeError):
    """Base class for OAuth state errors that map to protocol failures."""


class InvalidClient(OAuthStateError):
    """The client is unknown or revoked."""


class InvalidGrant(OAuthStateError):
    """The presented refresh token cannot be used."""


class InvalidTarget(OAuthStateError):
    """The token was issued for a different resource."""


# --- Records -----------------------------------------------------------------------------


@dataclass(frozen=True)
class ClientMetadata:
    """A registered client."""
    client_id: str
    redirect_uris: tuple[str, ...]
    client_name: str
    created_at: float
    last_authorized_at: float | None
    revoked_at: float | None
    is_static: bool


@dataclass(frozen=True)
class RegisteredClient:
    """A new client with its secret."""
    client: ClientMetadata
    client_secret: str


@dataclass(frozen=True)
class TokenMetadata:
    """An access token record."""
    token_id: str
    client_id: str
    resource: str
    issued_at: float
    expires_at: float


@dataclass(frozen=True)
class IssuedToken:
    """Tokens handed to a client."""
    access_token: str
    token: TokenMetadata
    refresh_token: str | None = None


# --- The store ---------------------------------------------------------------------------


class OAuthState:
    """OAuth state kept in SQLite."""

    def __init__(
        self,
        path: str | Path,
        *,
        legacy_path: str | Path | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        """Open the store at path."""
        self.path = Path(path).expanduser().absolute()
        self._legacy_path = Path(legacy_path).expanduser() if legacy_path else None
        self._clock = clock or time.time
        self._lock = threading.RLock()
        self._closed = False

        self._tighten_files()
        self._connection = sqlite3.connect(
            self.path,
            timeout=30,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        try:
            self._configure_connection()
            self._initialize_schema()
            self._import_legacy_clients()
        except BaseException:
            self._connection.close()
            self._closed = True
            raise

    def close(self) -> None:
        """Close the connection."""
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> OAuthState:
        """Enter the context."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close on exit."""
        self.close()

    # --- Clients -------------------------------------------------------------------------

    def register_client(
        self,
        redirect_uris: Sequence[str],
        *,
        client_name: str = "Obsidian Vault MCP Client",
    ) -> RegisteredClient:
        """Register a dynamic client."""
        redirects = tuple(dict.fromkeys(redirect_uris))
        now = self._clock()
        with self._transaction() as connection:
            while True:
                client_id = f"vault-mcp-{secrets.token_hex(8)}"
                exists = connection.execute(
                    "SELECT 1 FROM clients WHERE client_id = ?", (client_id,)
                ).fetchone()
                if exists is None:
                    break
            client_secret = secrets.token_hex(32)
            connection.execute(
                "INSERT INTO clients "
                "(client_id, secret_verifier, is_static, client_name, created_at) "
                "VALUES (?, ?, 0, ?, ?)",
                (client_id, _secret_verifier("client", client_secret), client_name, now),
            )
            connection.executemany(
                "INSERT INTO client_redirect_uris (client_id, redirect_uri) VALUES (?, ?)",
                ((client_id, uri) for uri in redirects),
            )
        client = self.get_client(client_id)
        assert client is not None
        return RegisteredClient(client=client, client_secret=client_secret)

    def ensure_static_client(
        self,
        client_id: str,
        *,
        client_name: str = "Obsidian Vault MCP Static Client",
    ) -> ClientMetadata:
        """Create the row of the client the operator configured, if it has none.

        Its secret and redirects live in the server configuration and are never stored
        here; the row carries its tokens and revocation.
        """
        now = self._clock()
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT is_static FROM clients WHERE client_id = ?", (client_id,)
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO clients "
                    "(client_id, secret_verifier, is_static, client_name, created_at) "
                    "VALUES (?, NULL, 1, ?, ?)",
                    (client_id, client_name, now),
                )
            elif not bool(existing["is_static"]):
                raise ValueError(f"client_id {client_id!r} is already registered dynamically")
        client = self.get_client(client_id)
        assert client is not None
        return client

    def revoke_client(self, client_id: str) -> bool:
        """Revoke a client; its tokens stop working with it. False if nothing changed."""
        with self._transaction() as connection:
            result = connection.execute(
                "UPDATE clients SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL",
                (self._clock(), client_id),
            )
        return result.rowcount == 1

    def get_client(self, client_id: str) -> ClientMetadata | None:
        """Client by id, if any."""
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM clients WHERE client_id = ?", (client_id,)
            ).fetchone()
            if row is None:
                return None
            return _client_from_row(row, self._redirects_for(client_id))

    def list_clients(self) -> tuple[ClientMetadata, ...]:
        """All clients, oldest first."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM clients ORDER BY created_at, client_id"
            ).fetchall()
            return tuple(
                _client_from_row(row, self._redirects_for(row["client_id"])) for row in rows
            )

    def verify_client_secret(self, client_id: str, client_secret: str) -> bool:
        """Check a client secret."""
        if not client_secret:
            return False
        with self._lock:
            row = self._connection.execute(
                "SELECT secret_verifier, revoked_at FROM clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
        if row is None or row["revoked_at"] is not None or row["secret_verifier"] is None:
            return False
        return hmac.compare_digest(
            bytes(row["secret_verifier"]), _secret_verifier("client", client_secret)
        )

    def client_redirect_uri_allowed(self, client_id: str, uri: str) -> bool:
        """Whether the client registered this redirect."""
        with self._lock:
            row = self._connection.execute(
                "SELECT 1 FROM clients AS c "
                "JOIN client_redirect_uris AS r USING (client_id) "
                "WHERE c.client_id = ? AND c.revoked_at IS NULL AND r.redirect_uri = ?",
                (client_id, uri),
            ).fetchone()
        return row is not None

    # --- Tokens --------------------------------------------------------------------------

    def issue_token_pair(self, *, client_id: str, resource: str) -> IssuedToken:
        """Access and refresh token for a client the caller has just authorized."""
        now = self._clock()
        with self._transaction() as connection:
            self._require_active_client(connection, client_id)
            issued = self._insert_tokens(
                connection, client_id=client_id, resource=resource, now=now, with_refresh=True
            )
            connection.execute(
                "UPDATE clients SET last_authorized_at = ? WHERE client_id = ?",
                (now, client_id),
            )
            return issued

    def issue_access_token(self, *, client_id: str, resource: str) -> IssuedToken:
        """Access token alone, for a client that authenticates with its own secret."""
        now = self._clock()
        with self._transaction() as connection:
            self._require_active_client(connection, client_id)
            return self._insert_tokens(
                connection, client_id=client_id, resource=resource, now=now, with_refresh=False
            )

    def lookup_access_token(self, access_token: str) -> TokenMetadata | None:
        """Metadata of a usable token, otherwise None."""
        parsed = _parse_token("v1", access_token)
        if parsed is None:
            return None
        token_id, secret = parsed
        with self._lock:
            row = self._connection.execute(
                "SELECT t.*, c.revoked_at AS client_revoked_at "
                "FROM access_tokens AS t JOIN clients AS c USING (client_id) "
                "WHERE t.token_id = ?",
                (token_id,),
            ).fetchone()
            # Read after the wait for the store, so a token that expired meanwhile is refused.
            now = self._clock()
        if row is None:
            return None
        if (
            row["client_revoked_at"] is not None
            or now >= float(row["expires_at"])
            or not hmac.compare_digest(
                bytes(row["secret_verifier"]), _secret_verifier("access-token", secret)
            )
        ):
            return None
        return TokenMetadata(
            token_id=str(row["token_id"]),
            client_id=str(row["client_id"]),
            resource=str(row["resource"]),
            issued_at=float(row["issued_at"]),
            expires_at=float(row["expires_at"]),
        )

    def redeem_refresh_token(
        self, *, refresh_token: str, client_id: str, resource_ok: Callable[[str], bool]
    ) -> IssuedToken:
        """Spend a refresh token and issue the next pair, in one transaction.

        A token that was already spent is refused and nothing else changes: the pair
        issued when it was spent stays valid. resource_ok judges the stored resource,
        so the store keeps no rule of how resources compare; the next pair gets the
        stored resource.
        """
        parsed = _parse_token("r1", refresh_token)
        if parsed is None:
            raise InvalidGrant("unknown refresh token")
        token_id, secret = parsed
        with self._transaction() as connection:
            # Read after the wait for the store, so a token that expired meanwhile is refused.
            now = self._clock()
            self._require_active_client(connection, client_id)
            row = connection.execute(
                "SELECT * FROM refresh_tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            if (
                row is None
                or row["client_id"] != client_id
                or not hmac.compare_digest(
                    bytes(row["secret_verifier"]), _secret_verifier("refresh-token", secret)
                )
            ):
                raise InvalidGrant("unknown refresh token")
            if row["consumed_at"] is not None:
                raise InvalidGrant("refresh token was already used")
            if now >= float(row["expires_at"]):
                raise InvalidGrant("refresh token expired")
            resource = str(row["resource"])
            if not resource_ok(resource):
                raise InvalidTarget("refresh token was issued for another resource")
            connection.execute(
                "UPDATE refresh_tokens SET consumed_at = ? WHERE token_id = ?",
                (now, token_id),
            )
            connection.execute(
                "UPDATE clients SET last_authorized_at = ? WHERE client_id = ?",
                (now, client_id),
            )
            return self._insert_tokens(
                connection, client_id=client_id, resource=resource, now=now, with_refresh=True
            )

    @staticmethod
    def _require_active_client(connection: sqlite3.Connection, client_id: str) -> None:
        """Refuse an unknown or revoked client."""
        row = connection.execute(
            "SELECT revoked_at FROM clients WHERE client_id = ?", (client_id,)
        ).fetchone()
        if row is None or row["revoked_at"] is not None:
            raise InvalidClient("unknown or revoked client")

    def _insert_tokens(
        self,
        connection: sqlite3.Connection,
        *,
        client_id: str,
        resource: str,
        now: float,
        with_refresh: bool,
    ) -> IssuedToken:
        """Store new tokens and return them."""
        # Access token
        token_id = _unused_id(connection, "access_tokens")
        token_secret = secrets.token_urlsafe(32)
        expires_at = now + ACCESS_TOKEN_TTL_SECONDS
        connection.execute(
            "INSERT INTO access_tokens "
            "(token_id, secret_verifier, client_id, resource, issued_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                token_id,
                _secret_verifier("access-token", token_secret),
                client_id,
                resource,
                now,
                expires_at,
            ),
        )
        # Refresh token
        refresh_token: str | None = None
        if with_refresh:
            refresh_id = _unused_id(connection, "refresh_tokens")
            refresh_secret = secrets.token_urlsafe(48)
            connection.execute(
                "INSERT INTO refresh_tokens "
                "(token_id, secret_verifier, client_id, access_token_id, resource, "
                "issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    refresh_id,
                    _secret_verifier("refresh-token", refresh_secret),
                    client_id,
                    token_id,
                    resource,
                    now,
                    now + REFRESH_TOKEN_TTL_SECONDS,
                ),
            )
            refresh_token = f"r1.{refresh_id}.{refresh_secret}"
        return IssuedToken(
            access_token=f"v1.{token_id}.{token_secret}",
            token=TokenMetadata(
                token_id=token_id,
                client_id=client_id,
                resource=resource,
                issued_at=now,
                expires_at=expires_at,
            ),
            refresh_token=refresh_token,
        )

    # --- Files, connection and schema ----------------------------------------------------

    def _tighten_files(self) -> None:
        """Private directory and database, tightened rather than refused.

        SQLite gives its sidecars the mode of the database file, so a new database is
        created 0600 before SQLite opens it. os.fchmod does not exist on Windows and is
        not needed: os.open sets the mode of a new file, os.chmod fixes an existing one.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        try:
            self._create_database_file()
        except FileExistsError:
            try:
                os.chmod(self.path, 0o600)
            except FileNotFoundError:
                # It vanished after the create was refused. SQLite must not be the one
                # to create it, or it gets the default mode.
                self._create_database_file()
        for suffix in ("-wal", "-shm"):
            with contextlib.suppress(FileNotFoundError):
                os.chmod(f"{self.path}{suffix}", 0o600)

    def _create_database_file(self) -> None:
        """Create the database file with mode 0600."""
        os.close(os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600))

    def _configure_connection(self) -> None:
        """Set pragmas and WAL mode."""
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 30000")
        self._connection.execute("PRAGMA synchronous = FULL")
        deadline = time.monotonic() + 30
        while True:
            try:
                mode = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
                break
            except sqlite3.OperationalError as exc:
                busy = exc.sqlite_errorcode in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
                if not busy or time.monotonic() >= deadline:
                    raise
                # The busy handler of SQLite does not cover every race over the journal mode.
                time.sleep(0.01)
        if str(mode).lower() != "wal":
            raise OAuthStateError("SQLite could not enable WAL mode")

    def _initialize_schema(self) -> None:
        """Create the tables once."""
        with self._lock:
            version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, SCHEMA_VERSION):
                raise OAuthStateError(f"unsupported OAuth state schema version {version}")
            script = (
                "BEGIN IMMEDIATE;\n"
                f"{_SCHEMA}\n"
                f"PRAGMA user_version = {SCHEMA_VERSION};\n"
                "COMMIT;\n"
            )
            try:
                self._connection.executescript(script)
            except BaseException:
                self._connection.rollback()
                raise

    # --- Import of the JSON registry -----------------------------------------------------

    def _import_legacy_clients(self) -> None:
        """Copy clients from the JSON registry that main kept, on every open.

        The file is only read. A client already in the store is left as it is, so a
        revoked client stays revoked and the store is the source of truth from then on.
        """
        if self._legacy_path is None:
            return
        # Read the registry
        try:
            with open(self._legacy_path) as registry_file:
                registry = json.load(registry_file)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            logger.warning(
                "OAuth client registry at %s is unreadable (%s); nothing imported",
                self._legacy_path,
                type(exc).__name__,
            )
            return
        if not isinstance(registry, dict):
            logger.warning(
                "OAuth client registry at %s is not an object; nothing imported",
                self._legacy_path,
            )
            return
        # Import the entries
        skipped = 0
        with self._transaction() as connection:
            for client_id, record in registry.items():
                if not _legacy_record_ok(record) or not _storable(
                    client_id, record["client_secret"], *record["redirect_uris"]
                ):
                    skipped += 1
                    continue
                inserted = connection.execute(
                    "INSERT OR IGNORE INTO clients "
                    "(client_id, secret_verifier, is_static, client_name, created_at) "
                    "VALUES (?, ?, 0, ?, ?)",
                    (
                        client_id,
                        _secret_verifier("client", record["client_secret"]),
                        "Obsidian Vault MCP Client",
                        _legacy_created_at(record.get("created_at"), self._clock()),
                    ),
                )
                if inserted.rowcount == 1:
                    connection.executemany(
                        "INSERT INTO client_redirect_uris (client_id, redirect_uri) "
                        "VALUES (?, ?)",
                        ((client_id, uri) for uri in dict.fromkeys(record["redirect_uris"])),
                    )
        # Report skipped entries
        if skipped:
            logger.warning(
                "OAuth client registry at %s: skipped %d entries that could not be read",
                self._legacy_path,
                skipped,
            )

    # --- Transactions and queries --------------------------------------------------------

    @contextlib.contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """One write transaction."""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def _redirects_for(self, client_id: str) -> tuple[str, ...]:
        """Redirects of one client."""
        rows = self._connection.execute(
            "SELECT redirect_uri FROM client_redirect_uris "
            "WHERE client_id = ? ORDER BY redirect_uri",
            (client_id,),
        ).fetchall()
        return tuple(str(row[0]) for row in rows)


# --- Helpers -----------------------------------------------------------------------------


def _secret_verifier(kind: str, secret: str) -> bytes:
    """Hash of a secret, separated by kind so one hash never verifies as another."""
    digest = hashlib.sha256()
    digest.update(b"obsidian-vault-mcp/oauth-state/v1\0")
    digest.update(kind.encode("ascii"))
    digest.update(b"\0")
    digest.update(secret.encode("utf-8"))
    return digest.digest()


def _legacy_record_ok(record: object) -> bool:
    """The same test main applied when it loaded its registry."""
    return (
        isinstance(record, dict)
        and isinstance(record.get("client_secret"), str)
        and isinstance(record.get("redirect_uris"), list)
        and all(isinstance(uri, str) for uri in record["redirect_uris"])
    )


def _storable(*texts: str) -> bool:
    """False for text that cannot be encoded, such as a lone surrogate."""
    try:
        for text in texts:
            text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _legacy_created_at(value: object, fallback: float) -> float:
    """The recorded moment when it is a real one, otherwise the fallback."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return fallback
    try:
        moment = float(value)
    except OverflowError:
        return fallback
    return moment if math.isfinite(moment) else fallback


def _parse_token(prefix: str, token: str) -> tuple[str, str] | None:
    """Split "<prefix>.<id>.<secret>" into id and secret, or None if it is not that."""
    if not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != prefix or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def _unused_id(connection: sqlite3.Connection, table: str) -> str:
    """A token id not in use."""
    while True:
        token_id = secrets.token_urlsafe(18)
        taken = connection.execute(
            f"SELECT 1 FROM {table} WHERE token_id = ?", (token_id,)
        ).fetchone()
        if taken is None:
            return token_id


def _client_from_row(row: sqlite3.Row, redirect_uris: tuple[str, ...]) -> ClientMetadata:
    """Client metadata from a row."""
    return ClientMetadata(
        client_id=str(row["client_id"]),
        redirect_uris=redirect_uris,
        client_name=str(row["client_name"]),
        created_at=float(row["created_at"]),
        last_authorized_at=(
            float(row["last_authorized_at"]) if row["last_authorized_at"] is not None else None
        ),
        revoked_at=float(row["revoked_at"]) if row["revoked_at"] is not None else None,
        is_static=bool(row["is_static"]),
    )
