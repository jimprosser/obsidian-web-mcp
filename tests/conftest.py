"""Test fixtures for the Obsidian vault MCP server."""

from pathlib import Path

import pytest


@pytest.fixture
def vault_dir(tmp_path, monkeypatch):
    """Create a temporary vault directory with sample files."""
    vault = tmp_path / "test-vault"
    vault.mkdir()

    # test-note.md with frontmatter
    (vault / "test-note.md").write_text(
        "---\nstatus: active\ntype: note\n---\n\nThis is a test note with some content.\n"
    )

    # subfolder/nested-note.md with frontmatter
    subfolder = vault / "subfolder"
    subfolder.mkdir()
    (subfolder / "nested-note.md").write_text(
        "---\nstatus: draft\ntype: client-hub\nclient: TestCorp\n---\n\nNested note content.\n"
    )

    # no-frontmatter.md
    (vault / "no-frontmatter.md").write_text("Just plain text, no frontmatter here.\n")

    # .obsidian/config.json (should be excluded)
    obsidian_dir = vault / ".obsidian"
    obsidian_dir.mkdir()
    (obsidian_dir / "config.json").write_text('{"theme": "dark"}')

    # Set environment variable for config module
    monkeypatch.setenv("VAULT_PATH", str(vault))
    monkeypatch.setenv("VAULT_MCP_TOKEN", "test-token-12345")

    # Reload config to pick up new env var
    import obsidian_vault_mcp.config as config
    from obsidian_vault_mcp import oauth

    oauth.close_oauth_state()
    config.VAULT_PATH = Path(str(vault))
    config.VAULT_OAUTH_STATE_PATH = tmp_path / "oauth-state" / "oauth.sqlite3"
    config.OAUTH_CLIENTS_PATH = tmp_path / "legacy" / "oauth_clients.json"
    config.VAULT_OAUTH_APPROVED_LEGACY_CLIENT_IDS = frozenset()

    yield vault
    oauth.close_oauth_state()
