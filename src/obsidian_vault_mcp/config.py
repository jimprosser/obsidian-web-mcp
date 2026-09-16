import os
from pathlib import Path

# Vault configuration
VAULT_PATH = Path(os.environ.get("VAULT_PATH", os.path.expanduser("~/Obsidian/MyVault")))
VAULT_MCP_TOKEN = os.environ.get("VAULT_MCP_TOKEN", "")
VAULT_MCP_PORT = int(os.environ.get("VAULT_MCP_PORT", "8420"))

# Daily-note tools. FOLDER "" means the vault root; FORMAT/TEMPLATE are strftime
# patterns. All optional with safe defaults; resolved paths still go through
# resolve_vault_path.
VAULT_DAILY_NOTES_FOLDER = os.environ.get("VAULT_DAILY_NOTES_FOLDER", "")
VAULT_DAILY_NOTES_FORMAT = os.environ.get("VAULT_DAILY_NOTES_FORMAT", "%Y-%m-%d").strip() or "%Y-%m-%d"
VAULT_DAILY_NOTES_TEMPLATE = os.environ.get("VAULT_DAILY_NOTES_TEMPLATE", "")

# HTTP path the MCP transport is mounted at. Defaults to "/" so connectors that
# POST to the root complete the handshake (#19) -- changing this default would
# break that, so leave it unless you deliberately host under a path prefix.
# Setting it (e.g. "/mcp") lets the server live alongside other services on one
# hostname behind a reverse proxy that cannot rewrite paths (Cloudflare Tunnel).
# Validated in validate_config(): must be absolute and must not collide with an
# auth-exempt path, or it would serve the vault on an unauthenticated route.
VAULT_MCP_PATH = os.environ.get("VAULT_MCP_PATH", "/")

# OAuth 2.0 client credentials (for Claude app integration)
VAULT_OAUTH_CLIENT_ID = os.environ.get("VAULT_OAUTH_CLIENT_ID", "vault-mcp-client")
VAULT_OAUTH_CLIENT_SECRET = os.environ.get("VAULT_OAUTH_CLIENT_SECRET", "")

# Interactive login gate on /oauth/authorize. The OAuth browser step authenticates
# the *human* before any authorization code is issued. Without this, anyone who can
# reach the URL can complete the flow and obtain a vault token (see issues #8/#29).
# The password is required on every authorization, so there is no ambient session
# cookie for a cross-site request to ride on.
VAULT_OAUTH_USERNAME = os.environ.get("VAULT_OAUTH_USERNAME", "obsidian")
VAULT_OAUTH_PASSWORD = os.environ.get("VAULT_OAUTH_PASSWORD", "")

# Allowed redirect URIs for the operator-configured client (VAULT_OAUTH_CLIENT_ID),
# comma-separated. Dynamically-registered clients carry their own redirect_uris; this
# governs only the static operator client. If empty, the operator client cannot use the
# browser authorization-code flow (it can still use the client_credentials grant).
VAULT_OAUTH_REDIRECT_URIS = [u.strip() for u in os.environ.get("VAULT_OAUTH_REDIRECT_URIS", "").split(",") if u.strip()]

# Where the dynamically-registered OAuth client registry is persisted. The registry is
# otherwise in-memory and wiped on every restart, which breaks already-connected MCP
# clients (they replay a client_id the restarted server no longer knows). Persisting it
# keeps connectors working across restarts. It holds per-client secrets, so it is written
# with 0600 perms (see oauth._save_clients). Override with OAUTH_CLIENTS_PATH.
OAUTH_CLIENTS_PATH = Path(os.environ.get(
    "OAUTH_CLIENTS_PATH",
    Path.home() / ".local" / "share" / "vault-mcp" / "oauth_clients.json",
))

# Network bind address. Defaults to loopback so the server is NOT exposed on the LAN;
# Cloudflare Tunnel reaches it over localhost. Set to 0.0.0.0 only if you deliberately
# want direct network exposure.
VAULT_MCP_HOST = os.environ.get("VAULT_MCP_HOST", "127.0.0.1")

# Extra hostnames allowed through the MCP library's DNS-rebinding protection,
# comma-separated. Loopback (127.0.0.1, localhost, [::1]) is always allowed; set this
# to your public tunnel/proxy hostname, e.g. "vault-mcp.example.com". Operator-supplied
# hosts are APPENDED to the loopback defaults in server.py, never replace them.
VAULT_MCP_ALLOWED_HOSTS = [h.strip() for h in os.environ.get("VAULT_MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]

# Which client IPs uvicorn trusts to set X-Forwarded-* headers. Because the server
# derives request.base_url from those headers and advertises it in OAuth discovery
# metadata + the RFC 9728 WWW-Authenticate challenge, trusting them from arbitrary
# sources lets an attacker spoof the advertised authorization-server / resource URL
# (X-Forwarded-Host: evil.example) -- a token-redirection vector. The server binds
# loopback and is reached by Cloudflare Tunnel / Caddy over localhost, so the only
# trustworthy forwarder is loopback. Defaults to uvicorn's own default, "127.0.0.1";
# override only if your reverse proxy connects from a different address (e.g. "::1").
# Never set this to "*".
VAULT_MCP_FORWARDED_ALLOW_IPS = os.environ.get("VAULT_MCP_FORWARDED_ALLOW_IPS", "127.0.0.1")

# Canonical public origin for every URL the server advertises -- the OAuth metadata
# endpoints (issuer / authorization_endpoint / token_endpoint / registration_endpoint /
# resource) and the WWW-Authenticate resource_metadata pointer. When set (e.g.
# "https://vault-mcp.example.com") it PINS those URLs so a spoofed Host / X-Forwarded-Host
# header cannot redirect OAuth discovery to an attacker-controlled server. When empty,
# the server falls back to the per-request base_url. A trailing slash is ignored.
VAULT_MCP_PUBLIC_URL = os.environ.get("VAULT_MCP_PUBLIC_URL", "").strip()


def advertised_base_url(request_base_url: str) -> str:
    """Return the canonical origin to advertise, with no trailing slash.

    Prefers the operator-pinned VAULT_MCP_PUBLIC_URL; falls back to the request's
    own base_url. Centralizing this keeps the OAuth metadata endpoints and the
    WWW-Authenticate challenge consistent and spoof-resistant.
    """
    return (VAULT_MCP_PUBLIC_URL or request_base_url).rstrip("/")

# Optional liveness heartbeat. When VAULT_MCP_HEARTBEAT_URL is set, the server GETs
# it every VAULT_MCP_HEARTBEAT_INTERVAL seconds from a daemon thread, for push-style
# uptime monitors (Uptime Kuma, Healthchecks.io, Cronitor, ...). Empty = disabled
# (the default); failures are logged, never fatal. The interval is kept as a raw
# string and parsed in validate_heartbeat() so a bad value fails closed at startup
# rather than crashing the whole server at import time.
VAULT_MCP_HEARTBEAT_URL = os.environ.get("VAULT_MCP_HEARTBEAT_URL", "").strip()
VAULT_MCP_HEARTBEAT_INTERVAL = os.environ.get("VAULT_MCP_HEARTBEAT_INTERVAL", "60").strip()


def validate_heartbeat() -> int | None:
    """Validate the heartbeat config; return the interval (seconds) when enabled.

    Returns None when the heartbeat is disabled (no URL). Raises ValueError (so
    server.main() can exit non-zero and fail CLOSED) when the URL scheme is not
    http(s) or the interval is not a positive integer -- a typo must not boot a
    server that silently never pings, or that tight-loops on interval 0.
    """
    url = VAULT_MCP_HEARTBEAT_URL
    if not url:
        return None

    from urllib.parse import urlsplit

    # The error messages below deliberately never echo the raw values: the URL is a
    # capability URL (secret in the path), and a misconfigured operator might swap the
    # URL/interval env vars -- and server.main() logs whatever this raises.
    try:
        parsed = urlsplit(url)
        port = parsed.port  # raises ValueError on a malformed port
    except ValueError:
        raise ValueError("VAULT_MCP_HEARTBEAT_URL has a malformed port")
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("VAULT_MCP_HEARTBEAT_URL must be an http(s) URL with a host")
    del port  # only accessed to trigger the malformed-port check

    try:
        interval = int(VAULT_MCP_HEARTBEAT_INTERVAL)
    except ValueError:
        raise ValueError(
            "VAULT_MCP_HEARTBEAT_INTERVAL must be an integer number of seconds"
        )
    if interval <= 0:
        raise ValueError("VAULT_MCP_HEARTBEAT_INTERVAL must be a positive integer")
    return interval


# Append-only JSONL audit log of vault mutations. When VAULT_AUDIT_LOG_PATH is set,
# every mutation appends one JSON record (UTC timestamp, SHA-256 hash of the bearer
# token, operation, target path, size + checksum before and after). Empty (the default)
# disables auditing entirely. The raw bearer token is never written -- only its SHA-256
# hash. The path is validated as writable at startup; an unwritable path fails the
# server closed (see server.main) rather than dropping records silently.
VAULT_AUDIT_LOG_PATH = os.environ.get("VAULT_AUDIT_LOG_PATH", "").strip()

# Also record read/search operations (opt-in). Off by default because reads are
# high-volume and may carry privacy weight; mutations are always logged once the audit
# log is enabled. Accepts 1/true/yes/on (case-insensitive).
VAULT_AUDIT_LOG_INCLUDE_READS = os.environ.get(
    "VAULT_AUDIT_LOG_INCLUDE_READS", ""
).strip().lower() in {"1", "true", "yes", "on"}

# Safety limits
MAX_CONTENT_SIZE = 1_000_000  # 1MB max write size
MAX_BINARY_SIZE = 10_000_000  # 10MB max binary write size (images/PDFs run larger than text)
MAX_BATCH_SIZE = 20           # Max files per batch operation
MAX_SEARCH_RESULTS = 50       # Max results per search
DEFAULT_SEARCH_RESULTS = 20
MAX_LIST_DEPTH = 5            # Max directory recursion depth
CONTEXT_LINES = 2             # Default lines of context in search results

# Directories to never expose or modify
EXCLUDED_DIRS = {".obsidian", ".trash", ".git", ".DS_Store"}

# Frontmatter index refresh interval (seconds)
FRONTMATTER_INDEX_DEBOUNCE = 5.0

# Rate limiting (requests per minute) -- track in-memory, enforce per-token
RATE_LIMIT_READ = 100
RATE_LIMIT_WRITE = 30


def _validate_mcp_path(path: str) -> None:
    """Reject a VAULT_MCP_PATH that is malformed or would expose the vault unauthenticated.

    The MCP transport mounts at exactly this path. The default "/" keeps behaviour
    byte-identical and is always valid. Any other value must be an absolute, clean
    path that does NOT land on (or under) an authentication-exempt route -- otherwise
    the bearer middleware would wave the vault transport through without a token.
    """
    if path == "/":
        return
    if not path.startswith("/"):
        raise ValueError(
            f"VAULT_MCP_PATH must be an absolute path starting with '/': {path!r}"
        )
    if path.endswith("/"):
        raise ValueError(
            f"VAULT_MCP_PATH must not end with a trailing slash: {path!r}"
        )
    if "?" in path or "#" in path or "//" in path:
        raise ValueError(
            "VAULT_MCP_PATH must be a clean path with no query string, fragment, "
            f"or empty segments: {path!r}"
        )
    if "%" in path or any(c.isspace() or ord(c) < 0x20 for c in path):
        raise ValueError(
            "VAULT_MCP_PATH must not contain percent-encoding, whitespace, or "
            f"control characters: {path!r}"
        )
    if any(seg in (".", "..") for seg in path.strip("/").split("/")):
        raise ValueError(
            f"VAULT_MCP_PATH must not contain '.' or '..' path segments: {path!r}"
        )
    # Imported lazily: auth imports config, so a top-level import here would cycle.
    from .auth import _AUTH_EXEMPT_PATHS

    reserved_prefixes = ("/oauth", "/.well-known")
    collides = path in _AUTH_EXEMPT_PATHS or any(
        path == prefix or path.startswith(prefix + "/") for prefix in reserved_prefixes
    )
    if collides:
        raise ValueError(
            f"VAULT_MCP_PATH {path!r} collides with an authentication-exempt route; "
            "mounting there would serve the vault without auth. Choose a path that is "
            "not /health and not under /oauth or /.well-known."
        )


def validate_config() -> None:
    """Validate operator-supplied configuration at startup.

    Called from server.main() before the server is built, so a bad value fails
    CLOSED with a clear message instead of booting a broken or insecure server.
    """
    _validate_mcp_path(VAULT_MCP_PATH)
