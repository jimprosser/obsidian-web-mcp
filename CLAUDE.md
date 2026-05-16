# CLAUDE.md

Operational context for this repo. Code-level docs are in README.md.

## How this server is actually deployed

- **Runtime:** Python via `uv`, entry point `vault-mcp` (Starlette + uvicorn on port `8420`).
- **Process manager:** launchd (`~/Library/LaunchAgents/com.marcelotoledo.vault-mcp.plist`). KeepAlive=true.
- **Tunnel:** Tailscale Funnel, NOT Cloudflare Tunnel as the README suggests. Public URL: `https://mt-mb-pro.tailcc1eaf.ts.net`.
- **Logs:** `~/Library/Logs/vault-mcp.log` (stdout) and `~/Library/Logs/vault-mcp-error.log` (stderr).
- **Secrets:** `.env` at repo root (`VAULT_PATH`, `VAULT_MCP_TOKEN`, `VAULT_OAUTH_CLIENT_SECRET`, `VAULT_MCP_ALLOWED_HOSTS`). plist sources it via `set -a; . .env; set +a`.
- **OAuth clients:** persisted to `.oauth_clients.json` so dynamically-registered clients survive restarts.

### Restart

```
launchctl kickstart -k gui/$(id -u)/com.marcelotoledo.vault-mcp
```

`kill <pid>` does nothing — launchd respawns immediately.

### Tunnel status

```
tailscale funnel status
```

## How Claude clients connect

There are two paths and one of them is broken upstream. Use the working one.

### Working: direct MCP config (USE THIS)

- **Claude Code:** `claude mcp add --scope user --transport http obsidian-vault https://mt-mb-pro.tailcc1eaf.ts.net --header "Authorization: Bearer <VAULT_MCP_TOKEN>"`
- **Claude Desktop:** entry in `~/Library/Application Support/Claude/claude_desktop_config.json` using `npx mcp-remote` as a stdio bridge. Already configured as `obsidian-vault`.

Both bypass Anthropic's broker entirely.

### Broken: "Custom Connector" UI (claude.ai web + Claude Desktop UI)

Don't bother. As of 2026-05, the broker aborts client-side before sending any HTTP request — zero traffic ever reaches the server. Confirmed by swapping the URL to a totally different domain (Cloudflare Tunnel) and reproducing the same instant failure with empty DevTools Network panel. Symptom matches multiple open issues at [anthropics/claude-ai-mcp](https://github.com/anthropics/claude-ai-mcp/issues) (search "zero inbound traffic").

If a future session sees `ofid_...` errors and wants to debug: the server is fine, the broker isn't. Don't go re-checking endpoints.

## Spec compliance notes

Server targets MCP spec 2025-06-18 + RFC 8414 / 9728. Specifically:

- `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp` both return metadata (broker probes the `/mcp`-suffixed variant).
- Same for `/.well-known/oauth-authorization-server[/mcp]`.
- Bearer auth middleware exempts `/.well-known/*` by prefix (not exact match) — required by RFC 9728.
- CORS middleware allows `claude.ai` / `anthropic.com` origins; without it, browser preflights fail before bearer auth even sees the request.
- Dynamic client registration response uses `token_endpoint_auth_method: "none"` (PKCE-only) per MCP spec preference.

If you touch `auth.py` or `oauth.py`, re-verify the four `/.well-known/*` paths return 200 with correct JSON, and `OPTIONS /mcp` with `Origin: https://claude.ai` returns 200 + CORS headers.

## Quick verification commands

```bash
# all four metadata endpoints should be 200
URL=https://mt-mb-pro.tailcc1eaf.ts.net
for p in /.well-known/oauth-{protected-resource,authorization-server}{,/mcp}; do
  curl -sS -o /dev/null -w "%{http_code} $p\n" "$URL$p"
done

# CORS preflight should be 200
curl -sS -i -X OPTIONS "$URL/mcp" -H "Origin: https://claude.ai" \
  -H "Access-Control-Request-Method: POST" | head -3
```
