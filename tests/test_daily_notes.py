"""Daily-note tools: path resolution, read (no create), append (create+template)."""

import json
from datetime import datetime

from obsidian_vault_mcp import config, server
from obsidian_vault_mcp.tools.daily import (
    vault_daily_note_append,
    vault_daily_note_path,
    vault_daily_note_read,
)


def _set_daily(monkeypatch, folder="", fmt="%Y-%m-%d", template=""):
    monkeypatch.setattr(config, "VAULT_DAILY_NOTES_FOLDER", folder)
    monkeypatch.setattr(config, "VAULT_DAILY_NOTES_FORMAT", fmt)
    monkeypatch.setattr(config, "VAULT_DAILY_NOTES_TEMPLATE", template)


def test_path_uses_format_and_folder(vault_dir, monkeypatch):
    _set_daily(monkeypatch, folder="journal", fmt="%Y-%m-%d")
    result = json.loads(vault_daily_note_path())
    assert result["path"] == "journal/" + datetime.now().strftime("%Y-%m-%d") + ".md"
    assert result["folder"] == "journal"


def test_read_missing_returns_error_and_does_not_create(vault_dir, monkeypatch):
    _set_daily(monkeypatch)
    result = json.loads(vault_daily_note_read())
    assert "error" in result and "not found" in result["error"].lower()
    assert not (vault_dir / result["path"]).exists()


def test_append_creates_with_template_then_appends(vault_dir, monkeypatch):
    _set_daily(monkeypatch, template="# %Y-%m-%d\n")
    first = json.loads(vault_daily_note_append("first line"))
    assert first["created"] is True
    assert first["daily_note"] is True

    path = json.loads(vault_daily_note_path())["path"]
    body = (vault_dir / path).read_text(encoding="utf-8")
    assert body.startswith("# " + datetime.now().strftime("%Y-%m-%d"))
    assert "first line" in body

    second = json.loads(vault_daily_note_append("second line"))
    assert second["created"] is False
    body2 = (vault_dir / path).read_text(encoding="utf-8")
    assert "first line" in body2 and "second line" in body2


def test_read_after_append_returns_content(vault_dir, monkeypatch):
    _set_daily(monkeypatch)
    vault_daily_note_append("hello daily")
    result = json.loads(vault_daily_note_read())
    assert "error" not in result
    assert "hello daily" in result["content"]


def test_tools_registered_and_append_wired(vault_dir, monkeypatch):
    for name in ("vault_daily_note_path", "vault_daily_note_read", "vault_daily_note_append"):
        assert server.mcp._tool_manager.get_tool(name) is not None
    _set_daily(monkeypatch)
    # server wrapper validates input and reaches the helper end to end
    result = json.loads(server.vault_daily_note_append("via wrapper"))
    assert result["created"] is True
    assert "via wrapper" in json.loads(vault_daily_note_read())["content"]
