"""Tests for the extension seam (server.serve(extensions) + Extension hooks).

The stock server (no extensions) is covered everywhere else; these assert that an
extension's tools/routes/index-hooks are wired in at the right points and that an
extension route is auth-protected like the rest of the surface.
"""

import pytest
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth as auth_module
from obsidian_vault_mcp import extensions, server
from obsidian_vault_mcp.frontmatter_index import FrontmatterIndex


class SpyExtension(extensions.Extension):
    """Records hook invocations and adds a probe route."""

    def __init__(self):
        self.calls = []
        self.registrar = None

    def register_tools(self, registrar):
        self.registrar = registrar
        self.calls.append("register_tools")

    def before_indexes_start(self, frontmatter_index):
        self.calls.append("before_indexes_start")

    def after_indexes_start(self, frontmatter_index):
        self.calls.append("after_indexes_start")

    def register_routes(self, app):
        async def probe(request):
            return JSONResponse({"ok": True})

        app.routes.insert(0, Route("/__ext_probe", probe, methods=["GET"]))
        self.calls.append("register_routes")

    def shutdown(self):
        self.calls.append("shutdown")


def test_bare_extension_is_all_noops():
    """The base Extension's hooks must do nothing (so subclasses opt in per-hook)."""
    ext = extensions.Extension()
    ext.register_tools(object())
    ext.before_indexes_start(object())
    ext.after_indexes_start(object())
    ext.shutdown()
    app = server.build_app([ext])  # register_routes no-op: app still builds
    assert app is not None


def test_build_app_registers_extension_routes(vault_dir):
    ext = SpyExtension()
    app = server.build_app([ext])
    paths = [getattr(r, "path", None) for r in app.routes]
    assert "/__ext_probe" in paths
    assert ext.calls == ["register_routes"]


def test_extension_route_is_bearer_protected(vault_dir, monkeypatch):
    """An extension route added before the middleware must require the bearer token."""
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")
    client = TestClient(server.build_app([SpyExtension()]))
    assert client.get("/__ext_probe").status_code == 401
    ok = client.get("/__ext_probe", headers={"Authorization": "Bearer secret-token"})
    assert ok.status_code == 200 and ok.json() == {"ok": True}


def test_extension_route_cannot_shadow_mcp_transport(vault_dir):
    class McpShadowExtension(extensions.Extension):
        def register_routes(self, app):
            async def shadow(_request):
                return JSONResponse({"unsafe": True})

            app.routes.insert(
                0,
                Route(server.VAULT_MCP_PATH, shadow, methods=["GET"]),
            )

    with pytest.raises(ValueError, match="MCP transport"):
        server.build_app([McpShadowExtension()])


def test_serve_invokes_lifecycle_hooks_in_order(vault_dir, monkeypatch):
    """serve() must call the hooks in the documented order and register shutdown."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    # server.py binds VAULT_PATH at import; point it at the temp vault for the is_dir check.
    monkeypatch.setattr(server, "VAULT_PATH", vault_dir)
    # Don't spawn a real watcher/threads.
    monkeypatch.setattr(server.frontmatter_index, "start", lambda: None)
    monkeypatch.setattr(server.frontmatter_index, "stop", lambda: None)
    registered = []
    monkeypatch.setattr(server.atexit, "register", lambda fn, *a, **k: registered.append(fn))

    ext = SpyExtension()
    server.serve([ext])

    assert ext.calls == [
        "register_tools",
        "before_indexes_start",
        "after_indexes_start",
        "register_routes",
    ]
    assert ext.shutdown in registered
    assert ext.registrar is server.tool_registrar
    assert not hasattr(ext.registrar, "resource")
    assert not hasattr(ext.registrar, "prompt")


def test_serve_accepts_a_generator_of_extensions(vault_dir, monkeypatch):
    """extensions is consumed multiple times -- a generator must not be half-applied."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    monkeypatch.setattr(server, "VAULT_PATH", vault_dir)
    monkeypatch.setattr(server.frontmatter_index, "start", lambda: None)
    monkeypatch.setattr(server.frontmatter_index, "stop", lambda: None)
    monkeypatch.setattr(server.atexit, "register", lambda fn, *a, **k: None)

    ext = SpyExtension()
    server.serve(e for e in [ext])  # a one-shot generator
    assert ext.calls == [
        "register_tools",
        "before_indexes_start",
        "after_indexes_start",
        "register_routes",
    ]


def _ext_adding(route):
    class _Ext(extensions.Extension):
        def register_routes(self, app):
            app.routes.insert(0, route)
    return _Ext()


async def _leak(request):
    return JSONResponse({"leak": True})


def test_extension_route_on_new_exempt_path_is_rejected(vault_dir):
    """A brand-new route on an exempt path must fail closed."""
    with pytest.raises(ValueError, match="auth-exempt"):
        server.build_app([_ext_adding(Route("/health", _leak, methods=["GET"]))])


def test_extension_route_shadowing_existing_exempt_path_is_rejected(vault_dir):
    """Inserting a route at an ALREADY-EXISTING exempt path (e.g. /oauth/token) ahead of
    the built-in must be caught — the identity-diff guard, not a path-string diff."""
    with pytest.raises(ValueError, match="auth-exempt"):
        server.build_app([_ext_adding(Route("/oauth/token", _leak, methods=["POST"]))])


def test_extension_wildcard_route_covering_exempt_path_is_rejected(vault_dir):
    """A catch-all pattern that would match an exempt path must fail closed."""
    with pytest.raises(ValueError, match="auth-exempt"):
        server.build_app([_ext_adding(Route("/{rest:path}", _leak, methods=["GET"]))])


def test_extension_mount_is_rejected(vault_dir):
    """Mounts are too broad to reason about — rejected outright."""
    from starlette.routing import Mount
    with pytest.raises(ValueError, match="[Mm]ount"):
        server.build_app([_ext_adding(Mount("/x", routes=[]))])


def test_benign_extension_route_is_allowed(vault_dir):
    """A normal non-exempt route (like the overlay's /search) builds fine."""
    app = server.build_app([_ext_adding(Route("/search", _leak, methods=["GET"]))])
    assert "/search" in [getattr(r, "path", None) for r in app.routes]


def test_extension_websocket_route_is_rejected(vault_dir):
    """WebSocketRoutes bypass the HTTP bearer middleware entirely -> rejected."""
    from starlette.routing import WebSocketRoute

    async def ws(websocket):  # pragma: no cover - never reached
        await websocket.accept()

    with pytest.raises(ValueError, match="WebSocketRoute"):
        server.build_app([_ext_adding(WebSocketRoute("/oauth/token", ws))])


def test_atexit_registration_order_runs_shutdown_before_index_stop(vault_dir, monkeypatch):
    """LIFO atexit: ext.shutdown registered after frontmatter_index.stop, so it runs first."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    monkeypatch.setattr(server, "VAULT_PATH", vault_dir)
    monkeypatch.setattr(server.frontmatter_index, "start", lambda: None)
    monkeypatch.setattr(server.frontmatter_index, "stop", lambda: None)
    registered = []
    monkeypatch.setattr(server.atexit, "register", lambda fn, *a, **k: registered.append(fn))

    ext = SpyExtension()
    server.serve([ext])
    assert registered.index(server.frontmatter_index.stop) < registered.index(ext.shutdown)


def test_main_runs_stock_server_with_no_extensions(monkeypatch):
    """main() must delegate to serve() with no extensions (backward compatible)."""
    captured = {}
    monkeypatch.setattr(server, "serve", lambda *a, **k: captured.setdefault("args", (a, k)))
    server.main()
    assert captured["args"] == ((), {})


# --- FrontmatterIndex listener + rebuild API (the index half of the seam) ---

def test_change_listener_fires_on_flush(vault_dir):
    idx = FrontmatterIndex()
    seen = []
    idx.add_change_listener(lambda path, exists: seen.append((path, exists)))
    idx.rebuild()

    note = vault_dir / "listener-note.md"
    note.write_text("---\nstatus: new\n---\nbody\n")
    idx._pending_paths.add(str(note))
    idx._flush_pending()

    assert (str(note), True) in seen
    assert any(r["path"] == "listener-note.md" for r in
               idx.search_by_field("status", "new", "exact"))


def test_listener_exception_does_not_break_indexing(vault_dir):
    idx = FrontmatterIndex()
    idx.add_change_listener(lambda path, exists: (_ for _ in ()).throw(RuntimeError("boom")))
    idx.rebuild()
    note = vault_dir / "robust.md"
    note.write_text("---\nk: v\n---\nx\n")
    idx._pending_paths.add(str(note))
    idx._flush_pending()  # must not raise despite the throwing listener
    assert any(r["path"] == "robust.md" for r in idx.search_by_field("k", "v", "exact"))


def test_rebuild_swaps_in_current_disk_state(vault_dir):
    idx = FrontmatterIndex()
    idx.rebuild()
    base = idx.file_count
    (vault_dir / "added.md").write_text("---\na: 1\n---\nx\n")
    idx.rebuild()
    assert idx.file_count == base + 1
