#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"

if [ -f "$ENV_FILE" ]; then
    echo ".env already exists at $ENV_FILE"
    read -rp "Overwrite? [y/N] " answer
    answer=${answer:-N}
    if [[ ! "$answer" =~ ^[Yy] ]]; then
        echo "Aborted."
        exit 0
    fi
fi

cat > "$ENV_FILE" <<EOF
VAULT_MCP_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")
VAULT_OAUTH_CLIENT_ID=vault-mcp-client
VAULT_OAUTH_CLIENT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
VAULT_PATH=$HOME/obsidian_vaults
VAULT_MCP_PORT=3001
EOF

chmod 600 "$ENV_FILE"
echo "Secrets written to $ENV_FILE (mode 600)"
