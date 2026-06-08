"""Integration tests for tool functions."""

import json

import pytest

from obsidian_vault_mcp.tools.read import vault_read, vault_batch_read
from obsidian_vault_mcp.tools.write import (
    vault_append,
    vault_batch_frontmatter_update,
    vault_edit,
    vault_write,
)
from obsidian_vault_mcp.models import VaultAppendInput, VaultEditInput
from obsidian_vault_mcp.tools.search import vault_search
from obsidian_vault_mcp.tools.manage import vault_list, vault_delete


def test_vault_read_returns_frontmatter(vault_dir):
    """vault_read returns parsed frontmatter."""
    result = json.loads(vault_read("test-note.md"))
    assert "error" not in result
    assert result["frontmatter"]["status"] == "active"
    assert result["frontmatter"]["type"] == "note"
    assert "test note" in result["content"]


def test_vault_write_creates_file(vault_dir):
    """vault_write creates a new file."""
    result = json.loads(vault_write("tools-test.md", "---\ntitle: Test\n---\n\nContent."))
    assert result["created"] is True
    assert result["size"] > 0
    assert (vault_dir / "tools-test.md").exists()


def test_vault_write_merge_frontmatter(vault_dir):
    """vault_write with merge_frontmatter preserves existing fields."""
    result = json.loads(vault_write(
        "test-note.md",
        "---\npriority: high\n---\n\nUpdated body.",
        merge_frontmatter=True,
    ))
    assert "error" not in result

    read_result = json.loads(vault_read("test-note.md"))
    assert read_result["frontmatter"]["status"] == "active"  # preserved
    assert read_result["frontmatter"]["priority"] == "high"  # new


def test_vault_edit_dry_run_returns_diff_without_writing(vault_dir):
    """vault_edit dry run previews a partial edit without rewriting the file."""
    before = (vault_dir / "test-note.md").read_text()

    result = json.loads(vault_edit(
        "test-note.md",
        [{"old_text": "some content", "new_text": "more focused content"}],
        dry_run=True,
    ))

    assert result["changed"] is False
    assert result["dry_run"] is True
    assert result["edits_applied"] == 1
    assert "-This is a test note with some content." in result["diff"]
    assert "+This is a test note with more focused content." in result["diff"]
    assert (vault_dir / "test-note.md").read_text() == before


def test_vault_edit_replaces_single_matching_fragment(vault_dir):
    """vault_edit changes only the requested fragment."""
    result = json.loads(vault_edit(
        "test-note.md",
        [{"old_text": "some content", "new_text": "more focused content"}],
    ))

    assert result["changed"] is True
    assert result["dry_run"] is False
    assert result["edits_applied"] == 1
    content = (vault_dir / "test-note.md").read_text()
    assert "This is a test note with more focused content." in content
    assert "some content" not in content


def test_vault_edit_accepts_str_replace_aliases(vault_dir):
    """vault_edit accepts old_str/new_str aliases for compatibility."""
    result = json.loads(vault_edit(
        "test-note.md",
        [{"old_str": "some content", "new_str": "more focused content"}],
    ))

    assert "error" not in result
    assert result["changed"] is True
    assert result["edits_applied"] == 1
    assert "more focused content" in (vault_dir / "test-note.md").read_text()


def test_vault_edit_rejects_mixed_canonical_and_alias_keys(vault_dir):
    """vault_edit rejects ambiguous edits that mix canonical keys and aliases."""
    before = (vault_dir / "test-note.md").read_text()

    result = json.loads(vault_edit(
        "test-note.md",
        [{
            "old_text": "some content",
            "old_str": "some content",
            "new_text": "more focused content",
        }],
    ))

    assert "error" in result
    assert "old_text" in result["error"]
    assert "old_str" in result["error"]
    assert result["changed"] is False
    assert (vault_dir / "test-note.md").read_text() == before


def test_vault_edit_missing_fragment_leaves_file_unchanged(vault_dir):
    """vault_edit does not write when old_text is missing."""
    before = (vault_dir / "test-note.md").read_text()

    result = json.loads(vault_edit(
        "test-note.md",
        [{"old_text": "not in this file", "new_text": "replacement"}],
    ))

    assert "error" in result
    assert result["changed"] is False
    assert result["edits_applied"] == 0
    assert (vault_dir / "test-note.md").read_text() == before


def test_vault_edit_repeated_fragment_leaves_file_unchanged(vault_dir):
    """vault_edit requires each old_text to appear exactly once."""
    (vault_dir / "repeat.md").write_text("repeat\nrepeat\n")

    result = json.loads(vault_edit(
        "repeat.md",
        [{"old_text": "repeat", "new_text": "once"}],
    ))

    assert "error" in result
    assert result["changed"] is False
    assert result["edits_applied"] == 0
    assert (vault_dir / "repeat.md").read_text() == "repeat\nrepeat\n"


def test_vault_edit_rolls_back_when_later_edit_fails(vault_dir):
    """vault_edit applies all edits only if every edit can be matched."""
    before = (vault_dir / "test-note.md").read_text()

    result = json.loads(vault_edit(
        "test-note.md",
        [
            {"old_text": "some content", "new_text": "more focused content"},
            {"old_text": "missing later edit", "new_text": "replacement"},
        ],
    ))

    assert "error" in result
    assert result["changed"] is False
    assert result["edits_applied"] == 0
    assert (vault_dir / "test-note.md").read_text() == before


def test_vault_append_adds_content_to_existing_file(vault_dir):
    """vault_append adds new content without requiring the full existing body."""
    result = json.loads(vault_append("no-frontmatter.md", "Appended note."))

    assert result["changed"] is True
    assert result["created"] is False
    assert result["appended"] is True
    assert (vault_dir / "no-frontmatter.md").read_text() == (
        "Just plain text, no frontmatter here.\n\n\nAppended note."
    )


def test_vault_append_creates_new_file(vault_dir):
    """vault_append creates a file when no target exists."""
    result = json.loads(vault_append("new/append.md", "Brand new note."))

    assert result["changed"] is True
    assert result["created"] is True
    assert result["appended"] is False
    assert (vault_dir / "new" / "append.md").read_text() == "Brand new note."


def test_vault_append_preserves_code_fences(vault_dir):
    """vault_append preserves fenced markdown exactly."""
    result = json.loads(vault_append(
        "no-frontmatter.md",
        "```python\nprint('hello')\n```",
    ))

    assert "error" not in result
    assert "```python\nprint('hello')\n```" in (vault_dir / "no-frontmatter.md").read_text()


def test_patch_style_inputs_preserve_edit_and_append_whitespace():
    """Patch-style models preserve markdown whitespace in small payloads."""
    edit_input = VaultEditInput(
        path="note.md",
        edits=[{"old_text": "  keep me\n", "new_text": "\n  keep replacement  "}],
    )
    append_input = VaultAppendInput(
        path="note.md",
        content="\n  appended block  \n",
        separator="\n---\n",
    )

    assert edit_input.edits[0].old_text == "  keep me\n"
    assert edit_input.edits[0].new_text == "\n  keep replacement  "
    assert append_input.content == "\n  appended block  \n"
    assert append_input.separator == "\n---\n"


def test_patch_style_inputs_normalize_str_replace_aliases():
    """Patch-style models normalize old_str/new_str to old_text/new_text."""
    edit_input = VaultEditInput(
        path="note.md",
        edits=[{"old_str": "  keep me\n", "new_str": "\n  keep replacement  "}],
    )

    dumped = edit_input.edits[0].model_dump()
    assert dumped == {
        "old_text": "  keep me\n",
        "new_text": "\n  keep replacement  ",
    }


def test_vault_search_finds_text(vault_dir):
    """vault_search finds text in files."""
    result = json.loads(vault_search("test note"))
    assert result["total_matches"] >= 1
    assert result["results"][0]["path"] == "test-note.md"


def test_vault_batch_read_handles_missing(vault_dir):
    """vault_batch_read returns errors for missing files without failing."""
    result = json.loads(vault_batch_read(
        ["test-note.md", "nonexistent.md"],
        include_content=True,
    ))
    assert result["found"] == 1
    assert result["missing"] == 1
    assert "error" in result["files"][1]


def test_vault_list_returns_items(vault_dir):
    """vault_list returns directory contents."""
    result = json.loads(vault_list(""))
    assert result["total"] >= 2
    names = [item["name"] for item in result["items"]]
    assert "test-note.md" in names
    assert ".obsidian" not in names


def test_vault_delete_requires_confirm(vault_dir):
    """vault_delete without confirm=true returns error."""
    vault_write("delete-me.md", "temp content")
    result = json.loads(vault_delete("delete-me.md", confirm=False))
    assert "error" in result
    assert (vault_dir / "delete-me.md").exists()  # still there
