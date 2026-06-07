"""Tests for environment-driven configuration (VAULT_MCP_ALLOWED_HOSTS)."""

import importlib

import pytest

import obsidian_vault_mcp.config as config_module


@pytest.fixture(autouse=True)
def _restore_config(monkeypatch):
    """Reload config after each test so the module-level parse doesn't leak."""
    yield
    monkeypatch.delenv("VAULT_MCP_ALLOWED_HOSTS", raising=False)
    importlib.reload(config_module)


def test_allowed_hosts_defaults_empty(monkeypatch):
    monkeypatch.delenv("VAULT_MCP_ALLOWED_HOSTS", raising=False)
    cfg = importlib.reload(config_module)
    assert cfg.VAULT_MCP_ALLOWED_HOSTS == []


def test_allowed_hosts_parsed_stripped_and_compacted(monkeypatch):
    monkeypatch.setenv("VAULT_MCP_ALLOWED_HOSTS", "vault-mcp.example.com, second.example.com ,")
    cfg = importlib.reload(config_module)
    # Whitespace trimmed; empty fragments (trailing comma) dropped.
    assert cfg.VAULT_MCP_ALLOWED_HOSTS == ["vault-mcp.example.com", "second.example.com"]


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
