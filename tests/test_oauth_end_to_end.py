"""OAuth state against the real serve() in its own process.

Upgrade: the state directory is the one main created, 0755, holding main's
oauth_clients.json: two claude.ai connectors registered with the same callback and one
client with no usable redirect at all, as a live registry holds them. The upgraded server
must start, tighten the directory instead of refusing it, keep every client, and leave the
JSON file untouched.

Revocation: vault-mcp-oauth, run as its own process against the same state, revokes a
client, and the running server refuses its token on the next request, without a restart.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

import pytest

from ._live_server import child_env, live_server

CALLBACK = "https://claude.ai/api/mcp/auth_callback"
REGISTRY = {
    "claude-web": {"client_secret": "s1", "redirect_uris": [CALLBACK]},
    "claude-desktop": {"client_secret": "s2", "redirect_uris": [CALLBACK]},
    "no-redirects": {"client_secret": "s3", "redirect_uris": []},
}


@pytest.fixture
def vault(tmp_path):
    """An empty vault."""
    v = tmp_path / "vault"
    v.mkdir()
    return v


@pytest.fixture
def legacy_state(tmp_path):
    """The state directory as main left it: 0755 with its JSON registry inside."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    os.chmod(state_dir, 0o755)
    registry = state_dir / "oauth_clients.json"
    registry.write_text(json.dumps(REGISTRY, indent=2))
    return registry


def _authorize_status(base_url, client_id):
    """Status of an authorization request for a client with the shared callback."""
    query = urllib.parse.urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": CALLBACK,
        "code_challenge": "x" * 43, "code_challenge_method": "S256",
    })
    url = f"{base_url}/oauth/authorize?{query}"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as err:
        return err.code


def test_upgrade_keeps_legacy_registry(tmp_path, vault, legacy_state):
    before = legacy_state.read_bytes()
    env = {"OAUTH_CLIENTS_PATH": str(legacy_state), "VAULT_OAUTH_PASSWORD": "hunter2"}

    with live_server(tmp_path, vault, env) as (base_url, _log):
        statuses = {cid: _authorize_status(base_url, cid) for cid in REGISTRY}

    assert statuses == {"claude-web": 200, "claude-desktop": 200, "no-redirects": 400}
    assert legacy_state.read_bytes() == before


@pytest.mark.skipif(os.name == "nt", reason="file modes are meaningless on Windows")
def test_upgrade_tightens_existing_state_dir(tmp_path, vault, legacy_state):
    env = {"OAUTH_CLIENTS_PATH": str(legacy_state)}

    with live_server(tmp_path, vault, env):
        # No request yet: whatever is on disk now was done at startup.
        modes = {
            path.name: path.stat().st_mode & 0o777
            for path in [legacy_state.parent, *legacy_state.parent.glob("oauth_state*")]
        }

    assert modes.pop("state") == 0o700
    assert "oauth_state.sqlite3" in modes
    assert set(modes.values()) == {0o600}, modes


# --- Revoking a client while the server runs ---------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Leave a 302 to the caller: the redirect target is the client, not a real site."""

    def redirect_request(self, *args, **kwargs):
        """Follow nothing."""
        return None


def _post(url, data=None, json_body=None, headers=None):
    """POST a form or JSON; return (status, headers, body) without following redirects."""
    if json_body is not None:
        body, kind = json.dumps(json_body).encode(), "application/json"
    else:
        body, kind = urllib.parse.urlencode(data).encode(), "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": kind, **(headers or {})})
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=10) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as err:
        return err.code, err.headers, err.read()


def _v1_token_over_http(base_url):
    """A client registers, signs in and redeems its code against the running server."""
    redirect = "https://app.example/cb"
    _s, _h, registered = _post(f"{base_url}/oauth/register",
                               json_body={"redirect_uris": [redirect]})
    client_id = json.loads(registered)["client_id"]
    verifier = "verifier-abc123_this-is-long-enough-for-pkce-xyz"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    status, headers, _b = _post(f"{base_url}/oauth/authorize", data={
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect,
        "code_challenge": challenge.rstrip(b"=").decode(), "code_challenge_method": "S256",
        "username": "obsidian", "password": "hunter2",
    })
    assert status == 302, status
    code = headers["Location"].split("code=")[1].split("&")[0]
    _s, _h, issued = _post(f"{base_url}/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": redirect, "code_verifier": verifier,
    })
    return client_id, json.loads(issued)["access_token"]


def _read_note(base_url, token):
    """Status of an MCP vault_read call with the token."""
    status, _h, _b = _post(f"{base_url}/", json_body={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "vault_read", "arguments": {"path": "note.md"}},
    }, headers={"Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream"})
    return status


def test_clients_revoke_takes_effect_on_running_server(tmp_path, vault):
    (vault / "note.md").write_text("# Note\n")
    registry = tmp_path / "state" / "oauth_clients.json"
    env = {"OAUTH_CLIENTS_PATH": str(registry), "VAULT_OAUTH_PASSWORD": "hunter2"}

    with live_server(tmp_path, vault, env) as (base_url, _log):
        client_id, token = _v1_token_over_http(base_url)
        before = _read_note(base_url, token)
        revoked = subprocess.run(
            [sys.executable, "-c",
             "from obsidian_vault_mcp.oauth_admin import main; raise SystemExit(main())",
             "clients", "revoke", client_id],
            env=child_env(tmp_path / "home", vault, 0, env),
            capture_output=True, text=True, timeout=60,
        )
        after = _read_note(base_url, token)

    assert token.startswith("v1.")
    assert before == 200
    assert revoked.returncode == 0, revoked.stderr
    assert json.loads(revoked.stdout) == {"client_id": client_id, "revoked": True}
    assert after == 401
