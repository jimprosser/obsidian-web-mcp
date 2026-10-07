"""Test fixtures for the Obsidian vault MCP server."""

import os
import tempfile
from pathlib import Path

import pytest

# Signed uploads are off unless VAULT_UPLOAD_URL_SECRET is set, and the tool is registered
# at import time, so the in-process suite needs the secret before obsidian_vault_mcp.server
# is imported. The off-by-default behaviour is covered separately, in a child process
# started without it (tests/test_signed_upload.py).
os.environ.setdefault("VAULT_UPLOAD_URL_SECRET", "suite-upload-secret")


@pytest.fixture(autouse=True)
def fresh_oauth_brakes(monkeypatch):
    """The login and registration brakes are process-wide by design (#97). Give every
    test fresh ones, so a suite that registers many clients does not trip them."""
    from obsidian_vault_mcp import oauth

    monkeypatch.setattr(oauth, "_login_failures",
                        oauth._SlidingLimit(oauth.LOGIN_FAILURE_LIMIT, oauth.LOGIN_FAILURE_WINDOW_SECONDS))
    monkeypatch.setattr(oauth, "_registrations",
                        oauth._SlidingLimit(oauth.REGISTRATION_LIMIT, oauth.REGISTRATION_WINDOW_SECONDS))


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
    config.VAULT_PATH = Path(str(vault))

    # Auditing is read from the environment at import, so a VAULT_AUDIT_LOG_PATH exported
    # in the developer's shell would take every server-level tool call in the suite into
    # their real audit log. Off by default here; tests that want it switch it on themselves
    # (see the audit_log fixture in test_audit.py), after this fixture has run.
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", "")
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", False)

    yield vault
