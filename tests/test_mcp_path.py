"""VAULT_MCP_PATH defaults to / and the spec-probe auth exemption is guarded.

The probe route itself is mounted in server.main() (needs a running app), so it
is not unit-tested here; the testable contract is (a) the config default/override
and (b) that auth only exempts GET/HEAD / when MCP is mounted off root.
"""

import importlib

from obsidian_vault_mcp import auth, config


def _reload(monkeypatch, value):
    """Reload config (+auth, which snapshots the path) with VAULT_MCP_PATH set/unset."""
    if value is None:
        monkeypatch.delenv("VAULT_MCP_PATH", raising=False)
    else:
        monkeypatch.setenv("VAULT_MCP_PATH", value)
    importlib.reload(config)
    importlib.reload(auth)


def test_path_defaults_to_root(monkeypatch):
    try:
        _reload(monkeypatch, None)
        assert config.VAULT_MCP_PATH == "/"
    finally:
        _reload(monkeypatch, None)


def test_path_override(monkeypatch):
    try:
        _reload(monkeypatch, "/mcp")
        assert config.VAULT_MCP_PATH == "/mcp"
    finally:
        _reload(monkeypatch, None)


def test_probe_not_exempt_at_root(monkeypatch):
    """Default mount (/) keeps GET/HEAD / fully authenticated."""
    try:
        _reload(monkeypatch, None)
        assert auth._AUTH_EXEMPT_METHOD_PATHS == set()
    finally:
        _reload(monkeypatch, None)


def test_probe_exempt_when_off_root(monkeypatch):
    """Hosting under a prefix frees / for the unauthenticated spec probe."""
    try:
        _reload(monkeypatch, "/mcp")
        assert ("GET", "/") in auth._AUTH_EXEMPT_METHOD_PATHS
        assert ("HEAD", "/") in auth._AUTH_EXEMPT_METHOD_PATHS
    finally:
        _reload(monkeypatch, None)
