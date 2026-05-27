#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [ -f ".env" ]; then
    set -o allexport
    # shellcheck source=../.env
    source .env
    set +o allexport
fi

missing=()
[ -z "${VAULT_MCP_TOKEN:-}" ] && missing+=("VAULT_MCP_TOKEN")
[ -z "${VAULT_OAUTH_CLIENT_SECRET:-}" ] && missing+=("VAULT_OAUTH_CLIENT_SECRET")

if [ ${#missing[@]} -gt 0 ]; then
    echo "ERROR: missing required secrets: ${missing[*]}"
    echo "Run ./scripts/generate_secrets.sh to create them."
    exit 1
fi

if [ -z "${VAULT_MCP_ALLOWED_HOSTS:-}" ]; then
    echo "INFO: VAULT_MCP_ALLOWED_HOSTS not set -- server only reachable via localhost"
fi

if [ ! -d ".venv" ]; then
    echo "Virtual environment not found."
    read -rp "Run 'uv sync' now? [Y/n] " answer
    answer=${answer:-Y}
    if [[ "$answer" =~ ^[Yy] ]]; then
        uv sync
    fi
fi

VAULT_PATH=${VAULT_PATH:-"$HOME/obsidian_vaults"} uv run vault-mcp
