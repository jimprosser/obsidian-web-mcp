"""The vault-mcp-oauth command: list and revoke OAuth clients in the local store.

It opens the same store the server uses, beside OAUTH_CLIENTS_PATH, importing the legacy
registry like every open, and it does so in Cloudflare Access mode too: this is local
administration, not a served endpoint. A revocation takes effect on a running server at
once, because every token lookup checks the client.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from typing import TextIO

from . import config
from .oauth import _state_path
from .oauth_state import ClientMetadata, OAuthState, OAuthStateError


# --- Arguments ---------------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    """The command line of vault-mcp-oauth."""
    parser = argparse.ArgumentParser(
        prog="vault-mcp-oauth", description="List and revoke OAuth clients of the vault MCP server."
    )
    resources = parser.add_subparsers(dest="resource", required=True)
    clients = resources.add_parser("clients", help="Registered OAuth clients")
    actions = clients.add_subparsers(dest="action", required=True)
    actions.add_parser("list", help="List every client and whether it is revoked")
    revoke = actions.add_parser("revoke", help="Revoke a client; its tokens stop working")
    revoke.add_argument("client_id")
    return parser


# --- Output ------------------------------------------------------------------------------


def _client_payload(client: ClientMetadata) -> dict[str, object]:
    """A client as printed: metadata only, the store holds no secret to print."""
    return {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "created_at": client.created_at,
        "is_static": client.is_static,
        "last_authorized_at": client.last_authorized_at,
        "redirect_uris": list(client.redirect_uris),
        "revoked_at": client.revoked_at,
    }


def _emit(stream: TextIO, payload: object) -> None:
    """Write one JSON line."""
    json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")


# --- Command -----------------------------------------------------------------------------


def main(argv: list[str] | None = None, *, stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    """Run one command and return its exit status."""
    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    args = _parser().parse_args(argv)
    state: OAuthState | None = None
    try:
        state = OAuthState(_state_path(), legacy_path=config.OAUTH_CLIENTS_PATH)
        if args.action == "list":
            _emit(output, [_client_payload(client) for client in state.list_clients()])
            return 0
        revoked = state.revoke_client(args.client_id)
        _emit(output, {"client_id": args.client_id, "revoked": revoked})
        # Nothing to revoke (unknown or already revoked) is not a success a script can build on.
        return 0 if revoked else 1
    except (OSError, OAuthStateError, sqlite3.Error) as exc:
        _emit(errors, {"error": str(exc)})
        return 1
    finally:
        if state is not None:
            state.close()


def _entrypoint() -> None:
    """Console script entry point."""
    raise SystemExit(main())
