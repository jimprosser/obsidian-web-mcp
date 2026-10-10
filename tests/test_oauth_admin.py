"""Tests for the vault-mcp-oauth command: list, revoke and set the access of clients."""

import json
from importlib.metadata import entry_points
from io import StringIO

import pytest

from obsidian_vault_mcp import config, oauth, oauth_admin

RESOURCE = "https://obsidian.example.xyz"


def _run(*argv):
    """Run the command in process; return its exit code, parsed stdout and raw stderr."""
    out, err = StringIO(), StringIO()
    code = oauth_admin.main(list(argv), stdout=out, stderr=err)
    return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()


def _registered(*, client_name="Obsidian Vault MCP Client"):
    """A client registered in the store the server uses."""
    return oauth.get_oauth_state().register_client(
        ["https://app.example/cb"], client_name=client_name
    ).client.client_id


def test_clients_list_shows_every_client_with_its_state():
    kept = _registered(client_name="sdk-test")
    revoked = _registered(client_name="Second Client")
    oauth.get_oauth_state().revoke_client(revoked)

    code, listed, _err = _run("clients", "list")

    assert code == 0
    by_id = {client["client_id"]: client for client in listed}
    assert by_id[kept]["client_name"] == "sdk-test"
    assert by_id[revoked]["client_name"] == "Second Client"
    assert by_id[kept]["revoked_at"] is None
    assert by_id[revoked]["revoked_at"] is not None
    assert by_id[kept]["redirect_uris"] == ["https://app.example/cb"]
    assert by_id[kept]["access"] == "write"
    assert not [key for client in listed for key in client if "secret" in key]


def test_clients_list_imports_the_legacy_registry():
    config.OAUTH_CLIENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.OAUTH_CLIENTS_PATH.write_text(json.dumps({
        "legacy-client": {"client_secret": "s", "redirect_uris": ["https://legacy.example/cb"]},
    }))

    code, listed, _err = _run("clients", "list")

    assert code == 0
    assert [client["client_id"] for client in listed] == ["legacy-client"]


def test_clients_revoke_stops_the_client_tokens():
    client_id = _registered()
    issued = oauth.get_oauth_state().issue_token_pair(client_id=client_id, resource=RESOURCE)

    code, answer, _err = _run("clients", "revoke", client_id)

    assert (code, answer) == (0, {"client_id": client_id, "revoked": True})
    assert oauth.get_oauth_state().lookup_access_token(issued.access_token) is None


@pytest.mark.parametrize("already_revoked", [False, True], ids=["unknown", "already-revoked"])
def test_clients_revoke_reports_nothing_to_revoke(already_revoked):
    client_id = _registered() if already_revoked else "vault-mcp-unknown"
    if already_revoked:
        oauth.get_oauth_state().revoke_client(client_id)

    code, answer, _err = _run("clients", "revoke", client_id)

    assert (code, answer) == (1, {"client_id": client_id, "revoked": False})


def test_clients_access_sets_the_level_the_client_tokens_carry():
    client_id = _registered()
    issued = oauth.get_oauth_state().issue_token_pair(client_id=client_id, resource=RESOURCE)

    code, answer, _err = _run("clients", "access", client_id, "read")
    _code, listed, _err = _run("clients", "list")

    assert (code, answer) == (0, {"client_id": client_id, "access": "read"})
    assert oauth.get_oauth_state().lookup_access_token(issued.access_token).access == "read"
    assert [client["access"] for client in listed] == ["read"]
    assert _run("clients", "access", client_id, "write")[:2] == (0, {"client_id": client_id, "access": "write"})
    assert oauth.get_oauth_state().lookup_access_token(issued.access_token).access == "write"


def test_clients_access_reports_an_unknown_client():
    code, answer, _err = _run("clients", "access", "vault-mcp-unknown", "read")

    assert (code, answer) == (1, {"client_id": "vault-mcp-unknown", "access": None})


def test_clients_access_refuses_a_level_it_does_not_know(capsys):
    client_id = _registered()

    with pytest.raises(SystemExit) as exited:
        _run("clients", "access", client_id, "admin")

    assert exited.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
    assert oauth.get_oauth_state().get_client(client_id).access == "write"


def test_state_that_cannot_open_is_an_error(tmp_path, monkeypatch):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    monkeypatch.setattr(config, "OAUTH_CLIENTS_PATH", blocker / "oauth_clients.json")

    code, listed, err = _run("clients", "list")

    assert (code, listed) == (1, None)
    assert "error" in json.loads(err)


def test_the_command_is_installed_as_vault_mcp_oauth():
    (installed,) = entry_points(group="console_scripts", name="vault-mcp-oauth")

    assert installed.load() is oauth_admin._entrypoint
