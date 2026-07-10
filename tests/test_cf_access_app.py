"""Integration tests for build_app() under Cloudflare Access mode."""

import pytest
from starlette.testclient import TestClient

from obsidian_vault_mcp import cf_access, config, server


@pytest.fixture
def cf_app(monkeypatch, tmp_path):
    """build_app() with CF mode ON and verify_access_token stubbed.

    "good-token" verifies; anything else raises CfAccessError.
    """
    vault = tmp_path / "vault"
    vault.mkdir()
    monkeypatch.setattr(config, "VAULT_PATH", vault)
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "myteam.cloudflareaccess.com")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "test-aud")
    monkeypatch.setattr(config, "VAULT_MCP_TOKEN", "static-secret")  # must NOT be accepted

    def fake_verify(header_value):
        if header_value == "good-token":
            return {"email": "claude@toye.io", "sub": "s"}
        raise cf_access.CfAccessError("bad")

    monkeypatch.setattr(cf_access, "verify_access_token", fake_verify)
    return TestClient(server.build_app(), raise_server_exceptions=False)


def test_health_ok_without_token(cf_app):
    assert cf_app.get("/health").status_code == 200


def test_oauth_routes_not_served(cf_app):
    # Probe WITH a valid token: past the auth gate, these routes are simply not mounted
    # in CF mode, so the router returns 404. (Unauthenticated they'd 401 — only /health
    # is exempt — so a valid token is what proves "not served".)
    hdr = {"Cf-Access-Jwt-Assertion": "good-token"}
    for path in (
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
    ):
        assert cf_app.get(path, headers=hdr).status_code == 404, path
    assert cf_app.get("/oauth/authorize", headers=hdr).status_code == 404
    assert cf_app.post("/oauth/token", headers=hdr).status_code == 404
    assert cf_app.post("/oauth/register", headers=hdr).status_code == 404


def test_static_bearer_not_accepted(cf_app):
    # A valid static bearer, but no CF header -> rejected in CF mode.
    r = cf_app.post("/", headers={"Authorization": "Bearer static-secret"})
    assert r.status_code == 401


def test_no_cf_header_is_401(cf_app):
    assert cf_app.post("/").status_code == 401


def test_invalid_cf_header_is_401(cf_app):
    r = cf_app.post("/", headers={"Cf-Access-Jwt-Assertion": "nope"})
    assert r.status_code == 401


def test_valid_cf_header_reaches_transport(cf_app):
    # A valid CF token clears auth; the request reaches the MCP transport, which then
    # rejects this non-MCP GET on its own terms (i.e. NOT a 401 from our middleware).
    r = cf_app.get("/", headers={"Cf-Access-Jwt-Assertion": "good-token"})
    assert r.status_code != 401


def test_mode_off_still_mounts_oauth(monkeypatch, tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    monkeypatch.setattr(config, "VAULT_PATH", vault)
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "")
    monkeypatch.setattr(config, "VAULT_MCP_TOKEN", "static-secret")
    client = TestClient(server.build_app(), raise_server_exceptions=False)
    # Discovery endpoint is served (bearer-exempt) when CF mode is off.
    assert client.get("/.well-known/oauth-protected-resource").status_code == 200
