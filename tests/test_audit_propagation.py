"""HTTP-level coverage for the load-bearing path the audit log depends on.

test_audit.py binds the request context in-frame; these drive a real request through
BearerAuthMiddleware so the principal / client_id / request_id propagation -- the one
thing the whole feature relies on -- is actually exercised (requested by upstream review
on #56). Also asserts the unauthenticated /health is liveness-only (no audit internals).
"""

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth as auth_module
from obsidian_vault_mcp import config, server
from obsidian_vault_mcp.context import current_request_context


def test_principal_propagates_to_sync_handler(monkeypatch):
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")

    def sync_probe(request):  # sync on purpose: mirrors how FastMCP runs vault_* tools
        ctx = current_request_context()
        return JSONResponse({"principal": ctx.get("principal"), "client": ctx.get("client"),
                             "request_id": ctx.get("request_id")})

    app = Starlette(routes=[Route("/probe", sync_probe)])
    app.add_middleware(auth_module.BearerAuthMiddleware)
    client = TestClient(app)

    r = client.get("/probe", headers={"Authorization": "Bearer secret-token",
                                      "User-Agent": "probe/1"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["principal"] == "secret-token"   # null here => token_id_hash null in prod
    assert body["client"] == "probe/1"
    assert body["request_id"]


def test_context_clean_outside_request():
    assert current_request_context() == {}


def test_health_is_liveness_only(vault_dir, monkeypatch):
    # Unauthenticated /health must not leak the audit log path or write counters.
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(vault_dir.parent / "audit.jsonl"))
    app = server.build_app()
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["audit"] == {"enabled": True}    # only the bool, nothing else
