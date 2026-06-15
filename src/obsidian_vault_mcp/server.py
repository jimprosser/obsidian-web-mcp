"""Obsidian Vault MCP Server.

Exposes read/write access to an Obsidian vault over Streamable HTTP.
Designed to run behind Cloudflare Tunnel for secure remote access.
"""

import atexit
import json
import logging
import sys
import threading
import time
import urllib.parse
import urllib.request
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .config import (
    VAULT_MCP_ALLOWED_HOSTS,
    VAULT_MCP_FORWARDED_ALLOW_IPS,
    VAULT_MCP_HEARTBEAT_URL,
    VAULT_MCP_HOST,
    VAULT_MCP_PATH,
    VAULT_MCP_PORT,
    VAULT_MCP_TOKEN,
    VAULT_PATH,
)
from .frontmatter_index import FrontmatterIndex

logger = logging.getLogger(__name__)

# Global frontmatter index instance
frontmatter_index = FrontmatterIndex()


# Liveness pings don't need the response body; read just enough to complete the
# request without pulling a large/hostile body into memory.
_HEARTBEAT_MAX_BYTES = 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects on the heartbeat GET.

    The configured URL is operator-trusted, but a redirect is not -- following one
    would let a compromised/typo'd monitor bounce the ping to an arbitrary target
    (incl. another scheme). Returning None makes urllib raise instead of follow.
    """

    def redirect_request(self, *args, **kwargs):
        return None


_heartbeat_opener = urllib.request.build_opener(_NoRedirect)


def _heartbeat_ping(url: str) -> None:
    """Send a single liveness GET. Split out from the loop so it is unit-testable.

    Does not follow redirects and reads at most _HEARTBEAT_MAX_BYTES of the body.
    """
    with _heartbeat_opener.open(url, timeout=10) as resp:
        resp.read(_HEARTBEAT_MAX_BYTES)


def _heartbeat_forever(url: str, interval: int) -> None:
    """Ping ``url`` every ``interval`` seconds for the process lifetime.

    Runs in a daemon thread started from main() -- NOT the per-request MCP lifespan,
    which fires on every request and would spawn a heartbeat per session. Failures
    are logged and swallowed so a flaky monitor can never take the server down.
    """
    # The heartbeat URL is a capability URL (the secret is in the path), so log only
    # the host + exception type on failure, never the full URL or exception string.
    host = urllib.parse.urlsplit(url).hostname or "?"
    while True:
        try:
            _heartbeat_ping(url)
        except Exception as e:
            logger.warning("Heartbeat ping to %s failed: %s", host, type(e).__name__)
        time.sleep(interval)


@asynccontextmanager
async def lifespan(server):
    """Per-request MCP lifespan.

    With stateless_http=True this runs on EVERY HTTP request, so it must NOT build
    or tear down the index -- doing so rebuilt the whole index per request and timed
    out large vaults (#28). The index is built once in main() before serving; here we
    only expose the already-built instance to tools.
    """
    yield {"frontmatter_index": frontmatter_index}


# Create the MCP server
mcp = FastMCP(
    "obsidian_web_mcp",
    stateless_http=True,
    json_response=True,
    # Mount path for the MCP transport. Defaults to "/" (via VAULT_MCP_PATH) so
    # connectors that POST to the root complete the handshake instead of 404ing
    # (#19); set VAULT_MCP_PATH to host under a prefix like "/mcp".
    streamable_http_path=VAULT_MCP_PATH,
    lifespan=lifespan,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[
            "127.0.0.1:*",
            "localhost:*",
            "[::1]:*",
            # Operator hostnames from VAULT_MCP_ALLOWED_HOSTS are appended to the
            # loopback defaults above (set it to your tunnel/proxy hostname).
            *VAULT_MCP_ALLOWED_HOSTS,
        ],
    ),
)


# --- Register all tools ---

from .tools.read import vault_read as _vault_read, vault_batch_read as _vault_batch_read
from .tools.write import (
    vault_append as _vault_append,
    vault_batch_frontmatter_update as _vault_batch_frontmatter_update,
    vault_edit as _vault_edit,
    vault_write as _vault_write,
)
from .tools.search import vault_search as _vault_search, vault_search_frontmatter as _vault_search_frontmatter
from .tools.manage import vault_list as _vault_list, vault_move as _vault_move, vault_delete as _vault_delete
from .tools.canvas import (
    vault_canvas_read as _vault_canvas_read,
    vault_canvas_add_node as _vault_canvas_add_node,
    vault_canvas_add_edge as _vault_canvas_add_edge,
)
from .tools.daily import (
    vault_daily_note_path as _vault_daily_note_path,
    vault_daily_note_read as _vault_daily_note_read,
    vault_daily_note_append as _vault_daily_note_append,
)
from .models import (
    VaultReadInput,
    VaultWriteInput,
    VaultEditInput,
    VaultEditOperationInput,
    VaultAppendInput,
    VaultBatchReadInput,
    VaultBatchFrontmatterUpdateInput,
    VaultSearchInput,
    VaultSearchFrontmatterInput,
    VaultListInput,
    VaultMoveInput,
    VaultDeleteInput,
    VaultCanvasReadInput,
    VaultCanvasAddNodeInput,
    VaultCanvasAddEdgeInput,
    VaultDailyNoteAppendInput,
)


@mcp.tool(
    name="vault_read",
    description="Read a file from the Obsidian vault, returning content, metadata, and parsed YAML frontmatter.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_read(path: str) -> str:
    """Read a file from the vault."""
    inp = VaultReadInput(path=path)
    return _vault_read(inp.path)


@mcp.tool(
    name="vault_batch_read",
    description="Read multiple files from the vault in one call. Handles missing files gracefully.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_batch_read(paths: list[str], include_content: bool = True) -> str:
    """Read multiple files at once."""
    inp = VaultBatchReadInput(paths=paths, include_content=include_content)
    return _vault_batch_read(inp.paths, inp.include_content)


@mcp.tool(
    name="vault_write",
    description="Write a file to the Obsidian vault. Supports frontmatter merging with existing files. Creates parent directories by default.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_write(path: str, content: str, create_dirs: bool = True, merge_frontmatter: bool = False) -> str:
    """Write a file to the vault."""
    inp = VaultWriteInput(path=path, content=content, create_dirs=create_dirs, merge_frontmatter=merge_frontmatter)
    return _vault_write(inp.path, inp.content, inp.create_dirs, inp.merge_frontmatter)


@mcp.tool(
    name="vault_edit",
    description=(
        "Patch an existing vault file with exact text replacements. Use this for token-efficient partial edits "
        "when only small fragments change; supports dry-run diff previews and avoids resending the full file. "
        "Each edit is an object {old_text, new_text}; old_text must match exactly once. Edits apply in order, "
        "and dry_run simulates that same in-order apply (each old_text is matched against the running document "
        "the earlier edits produce), so its diff and match counts predict the real apply, including chained edits."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_edit(path: str, edits: list[VaultEditOperationInput], dry_run: bool = False) -> str:
    """Patch a file with exact text replacements."""
    inp = VaultEditInput(path=path, edits=edits, dry_run=dry_run)
    return _vault_edit(
        inp.path,
        [edit.model_dump() for edit in inp.edits],
        inp.dry_run,
    )


@mcp.tool(
    name="vault_append",
    description=(
        "Append content to a vault file without sending the existing file body. Use this for token-efficient "
        "additions; creates the file when it does not exist."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_append(path: str, content: str, separator: str = "\n\n", create_dirs: bool = True) -> str:
    """Append content to a file."""
    inp = VaultAppendInput(path=path, content=content, separator=separator, create_dirs=create_dirs)
    return _vault_append(inp.path, inp.content, inp.separator, inp.create_dirs)


@mcp.tool(
    name="vault_batch_frontmatter_update",
    description="Update YAML frontmatter fields on multiple files without changing body content. Each update merges new fields into existing frontmatter.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_batch_frontmatter_update(updates: list[dict]) -> str:
    """Batch update frontmatter fields."""
    inp = VaultBatchFrontmatterUpdateInput(updates=updates)
    return _vault_batch_frontmatter_update(inp.updates)


@mcp.tool(
    name="vault_search",
    description="Search for text across vault files. Uses ripgrep if available, falls back to Python. Returns matching lines with context and frontmatter excerpts.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_search(
    query: str,
    path_prefix: str | None = None,
    file_pattern: str = "*.md",
    max_results: int = 20,
    context_lines: int = 2,
) -> str:
    """Search vault file contents."""
    inp = VaultSearchInput(query=query, path_prefix=path_prefix, file_pattern=file_pattern, max_results=max_results, context_lines=context_lines)
    return _vault_search(inp.query, inp.path_prefix, inp.file_pattern, inp.max_results, inp.context_lines)


@mcp.tool(
    name="vault_search_frontmatter",
    description="Search vault files by YAML frontmatter field values. Queries an in-memory index for fast results. Supports exact match, contains, and field-exists queries.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_search_frontmatter(
    field: str,
    value: str = "",
    match_type: str = "exact",
    path_prefix: str | None = None,
    max_results: int = 20,
) -> str:
    """Search by frontmatter fields."""
    inp = VaultSearchFrontmatterInput(field=field, value=value, match_type=match_type, path_prefix=path_prefix, max_results=max_results)
    return _vault_search_frontmatter(inp.field, inp.value, inp.match_type, inp.path_prefix, inp.max_results)


@mcp.tool(
    name="vault_list",
    description="List directory contents in the vault. Supports recursion depth, file/dir filtering, and glob patterns. Excludes .obsidian, .trash, .git directories.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_list(
    path: str = "",
    depth: int = 1,
    include_files: bool = True,
    include_dirs: bool = True,
    pattern: str | None = None,
) -> str:
    """List vault directory contents."""
    inp = VaultListInput(path=path, depth=depth, include_files=include_files, include_dirs=include_dirs, pattern=pattern)
    return _vault_list(inp.path, inp.depth, inp.include_files, inp.include_dirs, inp.pattern)


@mcp.tool(
    name="vault_move",
    description="Move a file or directory within the vault. Validates both source and destination paths.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_move(source: str, destination: str, create_dirs: bool = True) -> str:
    """Move a file or directory."""
    inp = VaultMoveInput(source=source, destination=destination, create_dirs=create_dirs)
    return _vault_move(inp.source, inp.destination, inp.create_dirs)


@mcp.tool(
    name="vault_delete",
    description="Delete a file by moving it to .trash/ in the vault root. Requires confirm=true as a safety gate. Does NOT hard delete.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_delete(path: str, confirm: bool = False) -> str:
    """Delete a file (move to .trash/)."""
    inp = VaultDeleteInput(path=path, confirm=confirm)
    return _vault_delete(inp.path, inp.confirm)


@mcp.tool(
    name="vault_canvas_read",
    description="Read an Obsidian .canvas file and return its parsed nodes and edges.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_canvas_read(path: str) -> str:
    """Read an Obsidian Canvas file."""
    inp = VaultCanvasReadInput(path=path)
    return _vault_canvas_read(inp.path)


@mcp.tool(
    name="vault_canvas_add_node",
    description=(
        "Append a node to an Obsidian .canvas file, creating the file if it does not exist. Requires type, x, y, "
        "width, height; an alphanumeric id is generated when omitted. Unknown node fields are preserved."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_canvas_add_node(path: str, node: dict) -> str:
    """Append a node to a Canvas file."""
    inp = VaultCanvasAddNodeInput(path=path, node=node)
    return _vault_canvas_add_node(inp.path, inp.node.model_dump(exclude_none=True, mode="json"))


@mcp.tool(
    name="vault_canvas_add_edge",
    description=(
        "Append an edge to an existing Obsidian .canvas file. Requires fromNode, toNode, and fromSide/toSide "
        "(top, right, bottom, left); both endpoints must reference existing node ids. An alphanumeric id is "
        "generated when omitted."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_canvas_add_edge(path: str, edge: dict) -> str:
    """Append an edge to a Canvas file."""
    inp = VaultCanvasAddEdgeInput(path=path, edge=edge)
    return _vault_canvas_add_edge(inp.path, inp.edge.model_dump(exclude_none=True, mode="json"))


@mcp.tool(
    name="vault_daily_note_path",
    description="Return today's daily-note path (server local date), derived from VAULT_DAILY_NOTES_FOLDER and VAULT_DAILY_NOTES_FORMAT. Does not read or create the file.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_daily_note_path() -> str:
    """Resolve today's daily-note path."""
    return _vault_daily_note_path()


@mcp.tool(
    name="vault_daily_note_read",
    description="Read today's daily note. Returns an error payload (does not create the note) when it does not exist.",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
)
def vault_daily_note_read() -> str:
    """Read today's daily note."""
    return _vault_daily_note_read()


@mcp.tool(
    name="vault_daily_note_append",
    description="Append content to today's daily note, creating it from VAULT_DAILY_NOTES_TEMPLATE when missing. Token-efficient daily logging without resending the note body.",
    annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
)
def vault_daily_note_append(content: str) -> str:
    """Append to today's daily note."""
    inp = VaultDailyNoteAppendInput(content=content)
    return _vault_daily_note_append(inp.content)


def build_app():
    """Assemble the authenticated Starlette app served to clients.

    MCP transport + OAuth routes + (off-root only) the unauthenticated spec probe
    at GET/HEAD / + the bearer-auth middleware. Extracted from main() so the exact
    composition that serves the vault can be exercised end-to-end in tests, rather
    than only the validation helper.
    """
    from starlette.responses import Response
    from starlette.routing import Route

    from .auth import BearerAuthMiddleware
    from .oauth import oauth_routes

    app = mcp.streamable_http_app()

    # MCP spec 2025-06-18 probe: GET/HEAD / answers with the protocol version.
    # Only mount it when MCP is NOT at root -- otherwise the transport owns
    # GET/HEAD / and this route would shadow it. (auth.py exempts GET/HEAD /
    # from bearer auth under the same VAULT_MCP_PATH != "/" guard.)
    if VAULT_MCP_PATH != "/":
        async def mcp_root_probe(request):
            return Response(
                status_code=200,
                headers={"MCP-Protocol-Version": "2025-06-18"},
            )

        app.routes.insert(0, Route("/", mcp_root_probe, methods=["GET", "HEAD"]))

    # Mount OAuth routes (these are excluded from bearer auth via the middleware)
    for route in oauth_routes:
        app.routes.insert(0, route)

    app.add_middleware(BearerAuthMiddleware)
    return app


def main():
    """Entry point. Run with streamable HTTP transport."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if not VAULT_PATH.is_dir():
        logger.error(f"Vault path does not exist: {VAULT_PATH}")
        sys.exit(1)

    # Validate operator config before serving; fail CLOSED on a bad value.
    try:
        from .config import validate_config
        validate_config()
    except ValueError as e:
        logger.error(f"Invalid configuration: {e}")
        sys.exit(1)

    if not VAULT_MCP_TOKEN:
        logger.warning("VAULT_MCP_TOKEN is not set -- auth will reject all requests")

    # Build the frontmatter index ONCE, before serving. With stateless_http the
    # per-request MCP lifespan would otherwise rebuild it on every request (#28).
    logger.info(f"Starting vault MCP server. Vault: {VAULT_PATH}")
    frontmatter_index.start()
    atexit.register(frontmatter_index.stop)

    # Optional liveness heartbeat. Daemon thread tied to the process (not the
    # per-request lifespan), started only when configured. Validated here so a bad
    # URL scheme or interval fails CLOSED instead of booting silently broken.
    try:
        from .config import validate_heartbeat
        heartbeat_interval = validate_heartbeat()
    except ValueError as e:
        logger.error(f"Invalid heartbeat configuration: {e}")
        sys.exit(1)
    if heartbeat_interval is not None:
        threading.Thread(
            target=_heartbeat_forever,
            args=(VAULT_MCP_HEARTBEAT_URL, heartbeat_interval),
            daemon=True,
            name="heartbeat",
        ).start()
        logger.info("Heartbeat enabled (interval: %ds)", heartbeat_interval)

    # Build the Starlette app with auth middleware and OAuth endpoints
    try:
        app = build_app()
        logger.info(f"Starting server on {VAULT_MCP_HOST}:{VAULT_MCP_PORT} with bearer auth + OAuth")
    except Exception as e:
        # Fail CLOSED: never fall back to an unauthenticated server.
        logger.error(f"Could not build the authenticated app: {e}")
        sys.exit(1)

    import uvicorn
    uvicorn.run(
        app,
        host=VAULT_MCP_HOST,
        port=VAULT_MCP_PORT,
        log_level="info",
        # Honor X-Forwarded-* ONLY from the trusted loopback proxy (Cloudflare
        # Tunnel / Caddy), never from arbitrary clients. Trusting "*" let any
        # caller spoof the advertised OAuth origin via X-Forwarded-Host.
        proxy_headers=True,
        forwarded_allow_ips=VAULT_MCP_FORWARDED_ALLOW_IPS,
    )


if __name__ == "__main__":
    main()
