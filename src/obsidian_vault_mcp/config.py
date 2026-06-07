import os
from pathlib import Path

# Vault configuration
VAULT_PATH = Path(os.environ.get("VAULT_PATH", os.path.expanduser("~/Obsidian/MyVault")))
VAULT_MCP_TOKEN = os.environ.get("VAULT_MCP_TOKEN", "")
VAULT_MCP_PORT = int(os.environ.get("VAULT_MCP_PORT", "8420"))

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

# Network bind address. Defaults to loopback so the server is NOT exposed on the LAN;
# Cloudflare Tunnel reaches it over localhost. Set to 0.0.0.0 only if you deliberately
# want direct network exposure.
VAULT_MCP_HOST = os.environ.get("VAULT_MCP_HOST", "127.0.0.1")

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
