"""Tests for environment-driven configuration (VAULT_MCP_ALLOWED_HOSTS)."""

import importlib
from pathlib import Path
import pytest

import obsidian_vault_mcp.config as config_module


@pytest.fixture(autouse=True)
def _restore_config(monkeypatch):
    yield
    for name in (
        "VAULT_MCP_ALLOWED_HOSTS",
        "VAULT_OAUTH_STATE_PATH",
        "VAULT_OAUTH_APPROVED_LEGACY_CLIENT_IDS",
        "VAULT_OAUTH_ACCESS_TOKEN_TTL_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    importlib.reload(config_module)


def test_oauth_state_defaults_are_lazy_and_bounded(monkeypatch):
    monkeypatch.delenv("VAULT_OAUTH_STATE_PATH", raising=False)
    monkeypatch.delenv("VAULT_OAUTH_APPROVED_LEGACY_CLIENT_IDS", raising=False)
    monkeypatch.delenv("VAULT_OAUTH_ACCESS_TOKEN_TTL_SECONDS", raising=False)

    cfg = importlib.reload(config_module)

    assert cfg.VAULT_OAUTH_STATE_PATH == (
        Path.home() / ".local/share/vault-mcp/oauth_state.sqlite3"
    )
    assert cfg.VAULT_OAUTH_APPROVED_LEGACY_CLIENT_IDS == frozenset()
    assert cfg.oauth_access_token_ttl_seconds() == 86_400


def test_oauth_state_environment_is_parsed_strictly(monkeypatch, tmp_path):
    state_path = tmp_path / "state" / "oauth.sqlite3"
    monkeypatch.setenv("VAULT_OAUTH_STATE_PATH", str(state_path))
    monkeypatch.setenv(
        "VAULT_OAUTH_APPROVED_LEGACY_CLIENT_IDS",
        " approved-a, approved-b, approved-a ",
    )
    monkeypatch.setenv("VAULT_OAUTH_ACCESS_TOKEN_TTL_SECONDS", "2592000")

    cfg = importlib.reload(config_module)

    assert cfg.VAULT_OAUTH_STATE_PATH == state_path
    assert cfg.VAULT_OAUTH_APPROVED_LEGACY_CLIENT_IDS == frozenset(
        {"approved-a", "approved-b"}
    )
    assert cfg.oauth_access_token_ttl_seconds() == 2_592_000


@pytest.mark.parametrize("value", ["", "0", "-1", "abc", "2592001"])
def test_invalid_oauth_access_token_ttl_fails_startup_validation(monkeypatch, value):
    monkeypatch.setenv("VAULT_OAUTH_ACCESS_TOKEN_TTL_SECONDS", value)
    cfg = importlib.reload(config_module)

    with pytest.raises(ValueError, match="VAULT_OAUTH_ACCESS_TOKEN_TTL_SECONDS"):
        cfg.validate_config()


def test_allowed_hosts_defaults_empty(monkeypatch):
    monkeypatch.delenv("VAULT_MCP_ALLOWED_HOSTS", raising=False)
    cfg = importlib.reload(config_module)
    assert cfg.VAULT_MCP_ALLOWED_HOSTS == []


def test_allowed_hosts_parsed_stripped_and_compacted(monkeypatch):
    monkeypatch.setenv(
        "VAULT_MCP_ALLOWED_HOSTS", "vault-mcp.example.com, second.example.com ,"
    )
    cfg = importlib.reload(config_module)
    # Whitespace trimmed; empty fragments (trailing comma) dropped.
    assert cfg.VAULT_MCP_ALLOWED_HOSTS == [
        "vault-mcp.example.com",
        "second.example.com",
    ]


def test_server_appends_to_loopback_defaults(monkeypatch):
    """server.py must APPEND operator hosts to loopback, never replace them."""
    monkeypatch.setenv("VAULT_MCP_ALLOWED_HOSTS", "vault-mcp.example.com")
    importlib.reload(config_module)
    server_module = importlib.import_module("obsidian_vault_mcp.server")
    importlib.reload(server_module)
    try:
        hosts = server_module.mcp.settings.transport_security.allowed_hosts
        assert "127.0.0.1:*" in hosts
        assert "localhost:*" in hosts
        assert "[::1]:*" in hosts
        assert "vault-mcp.example.com" in hosts
    finally:
        # Restore server module to ambient env so later test files are unaffected.
        monkeypatch.delenv("VAULT_MCP_ALLOWED_HOSTS", raising=False)
        importlib.reload(config_module)
        importlib.reload(server_module)
