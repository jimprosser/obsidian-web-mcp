"""Local metadata-only operations for durable OAuth state."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import TextIO

from . import config
from .oauth_state import OAuthState, OAuthStateError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault-mcp-oauth",
        description="Inspect, revoke, and back up local OAuth metadata.",
    )
    parser.add_argument(
        "--state-path", type=Path, default=config.VAULT_OAUTH_STATE_PATH
    )
    parser.add_argument("--vault-path", type=Path, default=config.VAULT_PATH)
    parser.add_argument("--legacy-path", type=Path, default=config.OAUTH_CLIENTS_PATH)
    parser.add_argument(
        "--approved-legacy-client-id",
        action="append",
        dest="approved_legacy_client_ids",
        default=list(config.VAULT_OAUTH_APPROVED_LEGACY_CLIENT_IDS),
    )
    parser.add_argument(
        "--access-token-ttl-seconds",
        type=int,
        default=config.oauth_access_token_ttl_seconds(),
    )
    resources = parser.add_subparsers(dest="resource", required=True)

    clients = resources.add_parser("clients", help="Client metadata operations")
    client_actions = clients.add_subparsers(dest="action", required=True)
    client_actions.add_parser("list", help="List client metadata")
    revoke_client = client_actions.add_parser(
        "revoke", help="Revoke a client and all of its state"
    )
    revoke_client.add_argument("client_id")

    tokens = resources.add_parser("tokens", help="Token metadata operations")
    token_actions = tokens.add_subparsers(dest="action", required=True)
    list_tokens = token_actions.add_parser("list", help="List token metadata")
    list_tokens.add_argument("--client-id")
    list_tokens.add_argument(
        "--active-only", action="store_true", help="Hide expired/revoked tokens"
    )
    revoke_token = token_actions.add_parser("revoke", help="Revoke one token")
    revoke_token.add_argument("token_id")

    backup = resources.add_parser("backup", help="Create an online SQLite backup")
    backup.add_argument("destination", type=Path)
    return parser


def _client_payload(client) -> dict[str, object]:
    return {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "created_at": client.created_at,
        "is_static": client.is_static,
        "last_authorized_at": client.last_authorized_at,
        "policy": client.policy,
        "redirect_uris": list(client.redirect_uris),
        "revoked_at": client.revoked_at,
    }


def _token_payload(token) -> dict[str, object]:
    return {
        "capabilities": list(token.capabilities),
        "client_id": token.client_id,
        "expires_at": token.expires_at,
        "issued_at": token.issued_at,
        "policy": token.policy,
        "resource": token.resource,
        "revoked_at": token.revoked_at,
        "token_id": token.token_id,
    }


def _emit(stream: TextIO, payload: object) -> None:
    json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Execute one local operation and return a process-style status code."""
    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    try:
        args = _parser().parse_args(argv)
    except ValueError as exc:
        _emit(errors, {"error": str(exc)})
        return 1
    state: OAuthState | None = None
    try:
        state = OAuthState(
            args.state_path,
            vault_path=args.vault_path,
            legacy_path=args.legacy_path,
            approved_legacy_client_ids=frozenset(args.approved_legacy_client_ids),
            access_token_ttl_seconds=args.access_token_ttl_seconds,
        )
        if args.resource == "clients" and args.action == "list":
            clients = [_client_payload(client) for client in state.list_clients()]
            _emit(output, clients)
            return 0
        if args.resource == "clients" and args.action == "revoke":
            revoked = state.revoke_client(args.client_id)
            _emit(
                output,
                {"client_id": args.client_id, "revoked": revoked},
            )
            return 0 if revoked else 1
        if args.resource == "tokens" and args.action == "list":
            tokens = state.list_tokens(include_inactive=not args.active_only)
            if args.client_id is not None:
                tokens = tuple(
                    token for token in tokens if token.client_id == args.client_id
                )
            _emit(output, [_token_payload(token) for token in tokens])
            return 0
        if args.resource == "tokens" and args.action == "revoke":
            revoked = state.revoke_token(args.token_id)
            _emit(
                output,
                {"revoked": revoked, "token_id": args.token_id},
            )
            return 0 if revoked else 1
        if args.resource == "backup":
            destination = state.backup(args.destination)
            _emit(output, {"backup": str(destination)})
            return 0
        raise AssertionError("unhandled OAuth admin command")
    except (OSError, ValueError, OAuthStateError, sqlite3.Error) as exc:
        _emit(errors, {"error": str(exc)})
        return 1
    finally:
        if state is not None:
            state.close()


def _entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    _entrypoint()
