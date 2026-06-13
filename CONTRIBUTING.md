# Contributing

Thanks for contributing. This document is the bar for getting a change merged — read it before opening a PR.

## What this project is

A **secure remote** MCP server for a **personal** Obsidian vault: OAuth 2.0, exposed through a Cloudflare Tunnel, atomic writes safe for Obsidian Sync. That framing is the filter for new work. The question for any feature isn't "is this a useful tool" — it's **"does it earn its attack surface on a server that's reachable over the network and holds someone's private notes."** Useful features that meaningfully widen that surface (arbitrary outbound fetches, new subprocess dependencies, new unauthenticated routes) need to clear a higher bar, be off by default, or stay out.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest            # full suite must pass before you open a PR
```

There is no CI on this repo. The test suite is the only gate, so a green local run is your evidence — say so in the PR.

## Scope and shape of a PR

- **One change per PR.** One tool, one fix, one feature. Don't bundle.
- **Rebase on `main`, never stack.** A PR built on top of another unmerged PR drags that PR's diff along and makes both impossible to review on their own merits. Land the dependency first, then rebase.
- **Match the existing conventions.** Config env vars use the `VAULT_MCP_*` prefix. Tools use the existing names and shapes (`vault_edit`, `vault_append`, etc.) — adopt them rather than introducing parallel names.
- **No new hard dependencies in the base install.** Anything heavy (embeddings, OCR, a vector index) ships as an optional extra (`pip install ".[name]"`), not in the default dependency set.

## Security requirements

These are not optional, and they're where most PRs need another pass:

- **Auth.** Bearer auth is enforced by a global middleware, with a small set of path-only exemptions. Any new route, and any setting that changes where routes mount, must be validated against that exemption set so it can't end up serving vault data on an unauthenticated path. **Fail closed**, never open.
- **Path handling.** Every vault path goes through `resolve_vault_path` (or the equivalent existing guard). Never build a filesystem path from request input without it. Re-validate the *resolved* path; don't trust a lexical check followed by a separate open (symlink TOCTOU).
- **Subprocesses.** Never `shell=True` on anything containing request input. Build an argv list. When passing a user value to a tool that takes flags (e.g. ripgrep), pass it in a way that can't be parsed as an option (`-e <query>`), or it's an argv-injection / RCE. Scrub the child environment — don't hand a hook or helper `VAULT_MCP_TOKEN` or OAuth secrets it doesn't need.
- **Outbound requests.** Don't follow redirects into private/loopback/link-local ranges (SSRF). Cap response sizes. Treat any URL the server fetches as attacker-influenced.
- **Logs.** Don't log secrets, tokens, or capability URLs (where the secret *is* the path). Log scheme + host + exception type, not the full value.

## Config and defaults

- New env vars are **validated at startup** and fail with a clear message — a typo or bad value must not boot a silently-broken server, and must not crash unrelated functionality at import time.
- Anything new and security-relevant is **off by default** and opt-in.
- Bridge-dependent tools (anything that needs an external plugin or the Obsidian Local REST API) **fail soft** when the dependency is absent — return a clear "not available," don't error.

## Writes

- All writes go through the **atomic write path** (tempfile + `os.replace`) so Obsidian Sync never sees a partial file. Don't write in place.
- Be careful with anything that merges into existing note content (frontmatter, edits) — round-trip fidelity matters; a bug here corrupts real notes.

## Tests

- Cover the **wiring**, not just the helper. A test that exercises a function in isolation but never the tool that calls it will pass even if the tool is disconnected — test the seam.
- Add a **negative / abuse test** for any new input (a leading-dash query, a path with `..`, an oversized payload, a malformed value).
- Tests that depend on an external binary or plugin (ripgrep, REST API) **skip cleanly** when it's absent (`@pytest.mark.skipif`).

## Docs

- Any new env var goes in the README's environment-variable table.
- Any new tool gets a one-line description of what it does and what it touches.
- Any new dependency (and why it's needed) is called out in the PR.

## PR checklist

Copy this into your PR description:

```
- [ ] One self-contained change, rebased on main (not stacked on another PR)
- [ ] Full test suite passes locally (`pytest`)
- [ ] New/abuse inputs covered by tests; the tool wiring is tested, not just helpers
- [ ] Auth: any new route/mount validated against the exempt set; fails closed
- [ ] Paths go through resolve_vault_path; resolved path re-validated
- [ ] No shell=True on request input; subprocess env scrubbed of secrets
- [ ] Outbound requests don't follow redirects to private ranges; response size capped
- [ ] No secrets/tokens/capability URLs in logs
- [ ] New config validated at startup, fails closed, off by default if risky
- [ ] Bridge/optional deps fail soft when absent; heavy deps are optional extras
- [ ] Writes go through the atomic write path
- [ ] README updated for new env vars / tools / dependencies
```
