"""Tests for auth middleware, OAuth metadata, and MCP spec 2025-06-18 endpoints."""

import importlib
import os

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient


@pytest.fixture
def app(monkeypatch):
    """Build a minimal Starlette app with the same wiring as server.main()."""
    monkeypatch.setenv("VAULT_MCP_TOKEN", "test-token-xyz")
    monkeypatch.setenv("VAULT_MCP_ALLOWED_HOSTS", "")

    import obsidian_vault_mcp.config as config
    importlib.reload(config)
    import obsidian_vault_mcp.auth as auth_mod
    importlib.reload(auth_mod)
    import obsidian_vault_mcp.oauth as oauth_mod
    importlib.reload(oauth_mod)

    async def echo(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/", echo, methods=["POST", "GET", "HEAD"]), *oauth_mod.oauth_routes])
    app.add_middleware(auth_mod.BearerAuthMiddleware)
    return app


def test_options_passes_auth_for_cors_preflight(app):
    """OPTIONS must not 401 — browsers strip credentials from preflights."""
    client = TestClient(app)
    response = client.options("/", headers={"Origin": "https://claude.ai"})
    assert response.status_code != 401


def test_protected_resource_metadata_is_public(app):
    """RFC 9728 endpoint must answer without bearer auth."""
    client = TestClient(app)
    response = client.get("/.well-known/oauth-protected-resource")
    assert response.status_code == 200
    body = response.json()
    assert "resource" in body
    assert "authorization_servers" in body
    assert body["bearer_methods_supported"] == ["header"]


def test_401_includes_www_authenticate_with_resource_metadata(app):
    """Spec-compliant clients discover the auth server via WWW-Authenticate."""
    client = TestClient(app)
    response = client.post("/", json={})
    assert response.status_code == 401
    challenge = response.headers.get("WWW-Authenticate", "")
    assert challenge.startswith("Bearer ")
    assert 'resource_metadata="' in challenge
    assert "/.well-known/oauth-protected-resource" in challenge


def test_authorization_server_metadata_still_public(app):
    """Existing RFC 8414 endpoint must keep working."""
    client = TestClient(app)
    response = client.get("/.well-known/oauth-authorization-server")
    assert response.status_code == 200
    assert "authorization_endpoint" in response.json()


def test_valid_bearer_passes(app):
    client = TestClient(app)
    response = client.post("/", json={}, headers={"Authorization": "Bearer test-token-xyz"})
    assert response.status_code == 200


def test_invalid_bearer_returns_401_with_challenge(app):
    client = TestClient(app)
    response = client.post("/", json={}, headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


def test_allowed_hosts_env_parsing(monkeypatch):
    """VAULT_MCP_ALLOWED_HOSTS env var feeds the allowed_hosts list."""
    monkeypatch.setenv("VAULT_MCP_ALLOWED_HOSTS", "vault.example.com, foo.tailnet.ts.net ,")
    import obsidian_vault_mcp.config as config
    importlib.reload(config)
    assert "vault.example.com" in config.VAULT_MCP_ALLOWED_HOSTS
    assert "foo.tailnet.ts.net" in config.VAULT_MCP_ALLOWED_HOSTS
    # Loopback defaults stay
    assert "127.0.0.1:*" in config.VAULT_MCP_ALLOWED_HOSTS
    # Empty entries are dropped
    assert "" not in config.VAULT_MCP_ALLOWED_HOSTS


def test_allowed_hosts_empty_env_is_just_defaults(monkeypatch):
    monkeypatch.delenv("VAULT_MCP_ALLOWED_HOSTS", raising=False)
    import obsidian_vault_mcp.config as config
    importlib.reload(config)
    assert config.VAULT_MCP_ALLOWED_HOSTS == ["127.0.0.1:*", "localhost:*", "[::1]:*"]
