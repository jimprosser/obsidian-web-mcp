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

All three paths work end-to-end against this server. Pick based on use case.

### Option A: Custom Connector via UI (recommended for claude.ai web + mobile)

claude.ai → Settings → Connectors → Add custom connector → `https://mt-mb-pro.tailcc1eaf.ts.net`. Broker handles OAuth (DCR + PKCE). Works on claude.ai web, Claude Desktop, and the mobile app from the same registration.

### Option B: Direct HTTP with static bearer (Claude Code)

```
claude mcp add --scope user --transport http obsidian-vault https://mt-mb-pro.tailcc1eaf.ts.net --header "Authorization: Bearer <VAULT_MCP_TOKEN>"
```

Bypasses the broker. Useful when you want a static-token connection without the OAuth dance.

### Option C: stdio bridge in `claude_desktop_config.json` (legacy)

`npx mcp-remote` block in `~/Library/Application Support/Claude/claude_desktop_config.json` with the static bearer. Works, but **don't use in combination with Option A** — having both Desktop connectors point at the same backend confuses Desktop's UI (collides on names / auth state, makes connect-state flap between "no tools" / "unavailable" / "authorization failed"). Pick A **or** C, not both.

### Troubleshooting if Connect fails with `ofid_...`

Before assuming a broker bug or spec issue, **do this first**:

1. **Full quit + relaunch `Tailscale.app`** (Cmd+Q the menubar app, then reopen). `tailscale funnel reset` alone is not enough — the Mac IPNExtension can get into a state where it stops forwarding the Anthropic outbound range (`160.79.104.0/21`) into the funnel even though local apps using the tailnet still work. A full app restart fixes this. Symptom: `step=start_error` / "Couldn't reach the MCP server" while Claude Code via static bearer keeps working.

2. **Confirm broker traffic now reaches the server**:
   ```
   tail -f ~/Library/Logs/vault-mcp.log | grep -E "160\.79\.|/.well-known"
   ```
   Trigger Connect; you should see GETs on `/.well-known/oauth-*` and POSTs from `160.79.106.x` within seconds. If not, restart Tailscale again or check `tailscale funnel status`.

3. **If Connect succeeds server-side but Desktop UI still shows error**, you probably have both Option A and Option C active. Remove one. The duplicate `obsidian-vault` block in `claude_desktop_config.json` is the usual culprit.

The server itself is spec-compliant; don't go re-checking endpoints unless step 1–3 don't help.

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
