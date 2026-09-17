"""Tests for the bearer-auth middleware's RFC 9728 WWW-Authenticate challenge."""

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth as auth_module


@pytest.fixture
def client(monkeypatch):
    # Bind a known token into the middleware's module namespace.
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")

    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", ok)])
    app.add_middleware(auth_module.BearerAuthMiddleware)
    return TestClient(app)


def test_missing_auth_returns_401_with_challenge(client):
    r = client.get("/")
    assert r.status_code == 401
    wa = r.headers.get("WWW-Authenticate", "")
    assert wa.startswith("Bearer ")
    assert "/.well-known/oauth-protected-resource" in wa
    assert 'resource_metadata="' in wa
    assert 'error="invalid_request"' in wa


def test_bad_token_returns_401_with_invalid_token_challenge(client):
    r = client.get("/", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401
    wa = r.headers.get("WWW-Authenticate", "")
    assert 'error="invalid_token"' in wa
    assert "/.well-known/oauth-protected-resource" in wa


def test_valid_token_passes_through(client):
    r = client.get("/", headers={"Authorization": "Bearer secret-token"})
    assert r.status_code == 200
    assert r.text == "ok"
    assert "WWW-Authenticate" not in r.headers


# --- The exemption check reads the decoded ASGI path, not request.url.path ---------------
#
# request.url.path is parsed back out of a URL string, so an encoded "?" or "#" in the
# path (%3F, %23) truncates it: "/health%3F/x" reads as "/health" to the middleware while
# the router matches the decoded "/health?/x". These go through build_app() so the real
# middleware stack and exempt set are what is tested.

from obsidian_vault_mcp import server  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402


@pytest.fixture
def real_app_client(vault_dir, monkeypatch):
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")
    return TestClient(server.build_app(), raise_server_exceptions=False)


@pytest.mark.parametrize("path", ["/health%3F/x", "/health%23/x", "/oauth/token%3F/x"])
def test_encoded_delimiter_does_not_borrow_an_exemption(real_app_client, path):
    assert real_app_client.get(path).status_code == 401
    assert real_app_client.post(path).status_code == 401


def test_route_behind_an_encoded_delimiter_still_needs_the_token(vault_dir, monkeypatch):
    """The consequence, not just the status code: a handler must not run tokenless."""
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")
    served = []

    class Ext:
        def register_routes(self, app):
            async def handler(request):
                served.append(request.scope["path"])
                return JSONResponse({"ok": True})

            app.routes.insert(0, Route("/health?/x", handler, methods=["GET"]))

    c = TestClient(server.build_app([Ext()]), raise_server_exceptions=False)

    assert c.get("/health%3F/x").status_code == 401
    assert served == []
    assert c.get("/health%3F/x", headers={"Authorization": "Bearer secret-token"}).status_code == 200


def test_exempt_paths_stay_exempt_with_a_real_query_string(real_app_client):
    assert real_app_client.get("/health").status_code == 200
    assert real_app_client.get("/health?probe=1").status_code == 200
