"""The live-server test helper must not inherit the developer's environment.

A child that inherits the shell picks up whatever the developer has exported. Some of
those values are not inert: VAULT_AUDIT_LOG_PATH sends test writes into a real audit log,
VAULT_MCP_HEARTBEAT_URL pings a real monitor, VAULT_MCP_HOST publishes the test server on
the network with a token that is in this repository, and VAULT_MCP_PATH moves the MCP
endpoint away from the "/" the helper talks to.
"""

from pathlib import Path

import pytest

pytest.importorskip("mcp")


def _helper():
    """Imported inside the tests, so the behaviour tests below can also run against an
    older revision of the helper that has no child_env."""
    from . import _live_server

    return _live_server

HOSTILE = {
    "VAULT_AUDIT_LOG_PATH": "/var/log/real-audit.jsonl",
    "VAULT_MCP_HEARTBEAT_URL": "https://uptime.example.com/ping/real",
    "VAULT_MCP_HOST": "0.0.0.0",
    "VAULT_MCP_PATH": "/mcp",
    "VAULT_OAUTH_CLIENT_SECRET": "developers-real-secret",
    "VAULT_UPLOAD_URL_SECRET": "developers-real-upload-secret",
}


@pytest.fixture
def exported(monkeypatch):
    for name, value in HOSTILE.items():
        monkeypatch.setenv(name, value)


def test_no_vault_setting_leaks_in_from_the_shell(exported, tmp_path):
    env = _helper().child_env(tmp_path / "home", tmp_path / "vault", 8999)

    leaked = {name: env[name] for name, value in HOSTILE.items() if env.get(name) == value}
    assert leaked == {}, leaked


def test_the_settings_the_helper_owns_are_set(exported, tmp_path):
    env = _helper().child_env(tmp_path / "home", tmp_path / "vault", 8999)

    assert env["VAULT_PATH"] == str(tmp_path / "vault")
    assert env["VAULT_MCP_TOKEN"] == _helper().TOKEN
    assert env["VAULT_MCP_HOST"] == "127.0.0.1"
    assert env["VAULT_MCP_PATH"] == "/"
    assert env["VAULT_MCP_PORT"] == "8999"
    assert env["HOME"] == str(tmp_path / "home") == env["USERPROFILE"]


def test_only_process_basics_and_explicit_extras_are_passed(exported, tmp_path):
    env = _helper().child_env(tmp_path / "home", tmp_path / "vault", 8999, {"VAULT_UPLOAD_MAX_BYTES": "1000"})

    allowed = set(_helper()._PASSTHROUGH) | {
        "HOME", "USERPROFILE", "PYTHONUNBUFFERED", "VAULT_PATH", "VAULT_MCP_TOKEN",
        "VAULT_MCP_HOST", "VAULT_MCP_PORT", "VAULT_MCP_PATH", "VAULT_MCP_PUBLIC_URL",
        "VAULT_UPLOAD_MAX_BYTES",
    }
    assert set(env) <= allowed, set(env) - allowed
    assert env["VAULT_UPLOAD_MAX_BYTES"] == "1000"


def test_a_child_can_actually_start_with_this_environment(tmp_path):
    """The allowlist must be enough to run Python at all; an over-trimmed env would only
    show up as a server that never comes up."""
    import subprocess
    import sys

    env = _helper().child_env(tmp_path / "home", tmp_path / "vault", 8999)
    result = subprocess.run(
        [sys.executable, "-c", "import obsidian_vault_mcp, os; print(os.environ['VAULT_PATH'])"],
        env=env, capture_output=True, text=True, timeout=120,
    )

    assert result.returncode == 0, result.stderr[-800:]
    assert result.stdout.strip() == str(tmp_path / "vault")

# --- Behaviour, not just the dict: these run against any version of the helper ---------

@pytest.fixture
def vault(tmp_path):
    v = tmp_path / "vault"
    v.mkdir()
    (v / "note.md").write_text("# Note\n", encoding="utf-8")
    return v


def test_an_exported_audit_log_path_gets_no_test_writes(tmp_path, vault, monkeypatch):
    """A developer's real audit log must stay untouched by the suite."""
    helper = _helper()
    call_tool_over_http, live_server = helper.call_tool_over_http, helper.live_server

    developers_log = tmp_path / "developers-audit.jsonl"
    monkeypatch.setenv("VAULT_AUDIT_LOG_PATH", str(developers_log))

    with live_server(tmp_path, vault) as (base_url, _log):
        result = call_tool_over_http(base_url, "vault_write", {"path": "neu.md", "content": "inhalt\n"})

    assert "error" not in result, result
    assert (vault / "neu.md").exists(), "negative control: the write did not happen"
    assert not developers_log.exists(), "the child wrote into the exported audit log"


def test_an_exported_mcp_path_does_not_move_the_endpoint(tmp_path, vault, monkeypatch):
    """The helper talks to "/". An inherited VAULT_MCP_PATH would move the endpoint and
    break every test built on the helper."""
    helper = _helper()
    call_tool_over_http, live_server = helper.call_tool_over_http, helper.live_server

    monkeypatch.setenv("VAULT_MCP_PATH", "/mcp")

    with live_server(tmp_path, vault) as (base_url, _log):
        result = call_tool_over_http(base_url, "vault_read", {"path": "note.md"})

    assert "# Note" in result.get("content", ""), result
