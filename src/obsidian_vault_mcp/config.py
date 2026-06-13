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

# Safety limits
MAX_CONTENT_SIZE = 1_000_000  # 1MB max write size
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
