"""Extension seam for the vault MCP server.

Lets a downstream package add tools, HTTP routes, and index hooks WITHOUT forking
server.py. The stock server runs with no extensions (`server.main()` -> `serve()`),
so every hook below is a no-op by default and the public server's behavior is
unchanged unless an operator passes their own extension to `server.serve(...)`.

A custom deployment provides its own console entry point, e.g.:

    from obsidian_vault_mcp.server import serve
    from my_pkg import MyExtension
    def main() -> None:
        serve([MyExtension()])

Override only the hooks you need; the rest stay no-ops.

To react to vault mutations *as operations* (a provenance-aware commit, an audit
log, a webhook), subscribe from `before_indexes_start` via the write-event seam in
`write_events` (`register_write_listener` / `fire_write`) -- the write-side mirror of
`FrontmatterIndex.add_change_listener`.

TRUST MODEL
-----------
Extensions are FULLY-TRUSTED, in-process code that the operator chooses to load.
An extension runs with the server's full privileges: it can read the bearer token
and OAuth secrets from the environment, read/write the vault, and mutate any route.
This is NOT a sandbox -- only load extensions you wrote or trust, exactly as you
would any dependency. `build_app()` includes a best-effort FOOTGUN check that fails
closed if an extension's `register_routes` adds a route on an auth-exempt path (so
an honest mistake can't silently expose an unauthenticated endpoint), but that is a
guardrail for accidents, not a security boundary against a hostile extension.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # imported lazily / only for typing to avoid import cycles
    from starlette.applications import Starlette

    from .frontmatter_index import FrontmatterIndex
    from .authorization import ToolRegistrar


class Extension:
    """Base class for a server extension. Subclass and override the hooks you need.

    Lifecycle, in the order `server.serve()` invokes them:

      1. register_tools(registrar)    add tools through the policy-aware registrar
                                      before the ASGI app / schema is built.
      2. before_indexes_start(index)  runs before the frontmatter index starts --
                                      e.g. attach a change listener so no change is
                                      missed between build and listener attach.
      3. after_indexes_start(index)   runs after the index is built and watching --
                                      e.g. start a periodic reconcile loop.
      4. register_routes(app)         add Starlette routes BEFORE the bearer-auth
                                      middleware is attached, so the routes are
                                      bearer-protected. Do NOT register a route on
                                      the MCP transport path or an auth-exempt path
                                      (/health, /oauth/*, /.well-known/*, or the
                                      off-root GET/HEAD / probe). A transport
                                      collision could bypass per-client MCP policy;
                                      an exempt collision would be unauthenticated.
                                      build_app() rejects both at startup.
      5. shutdown()                   registered with atexit; runs at process exit.
    """

    def register_tools(self, registrar: "ToolRegistrar") -> None:  # noqa: D401
        """Register MCP tools through the policy-aware registrar."""

    def before_indexes_start(self, frontmatter_index: "FrontmatterIndex") -> None:
        """Prepare before the frontmatter index is built and starts watching."""

    def after_indexes_start(self, frontmatter_index: "FrontmatterIndex") -> None:
        """Run after the frontmatter index is built and watching."""

    def register_routes(self, app: "Starlette") -> None:
        """Add Starlette routes to the app before the auth middleware is attached."""

    def shutdown(self) -> None:
        """Release resources at process exit (registered via atexit)."""
