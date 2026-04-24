"""Integration tests for tool functions."""

import json

import pytest

from obsidian_vault_mcp.tools.read import vault_read, vault_batch_read
from obsidian_vault_mcp.tools.write import vault_write, vault_batch_frontmatter_update
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


def test_vault_write_blocks_checkbox_by_default(vault_dir):
    """vault_write rejects checkboxes when allow_checkboxes is False (default)."""
    result = json.loads(vault_write("blocked.md", "intro\n\n- [ ] should not write\n"))
    assert "error" in result
    assert "checkbox" in result["error"].lower()
    assert not (vault_dir / "blocked.md").exists()


def test_vault_write_allows_checkbox_when_opted_in(vault_dir):
    """vault_write writes checkboxes when allow_checkboxes=True."""
    result = json.loads(vault_write(
        "tasks.md",
        "- [ ] task 1\n- [x] done\n",
        allow_checkboxes=True,
    ))
    assert "error" not in result
    assert result["created"] is True
    assert (vault_dir / "tasks.md").exists()


@pytest.mark.parametrize(
    "line",
    [
        "- [ ] dash empty",
        "- [x] dash done lower",
        "- [X] dash done upper",
        "* [ ] star empty",
        "* [x] star done",
        "+ [ ] plus empty",
        "+ [X] plus done upper",
        "  - [ ] indented",
        "\t- [x] tab indented",
    ],
)
def test_vault_write_detects_checkbox_variants(vault_dir, line):
    """Every Markdown checkbox variant Task Forge sees should be blocked."""
    result = json.loads(vault_write("variant.md", f"prose\n\n{line}\n"))
    assert "error" in result, f"Failed to block: {line!r}"
    assert "checkbox" in result["error"].lower()


def test_vault_write_ignores_checkbox_in_fenced_code_block(vault_dir):
    """Checkboxes inside ``` fenced code blocks must NOT be blocked (Task Forge ignores them)."""
    content = (
        "Some prose explaining the syntax.\n\n"
        "```markdown\n"
        "- [ ] this is a code example, not a real task\n"
        "- [x] same\n"
        "```\n\n"
        "More prose.\n"
    )
    result = json.loads(vault_write("code-example.md", content))
    assert "error" not in result, result
    assert result["created"] is True


def test_vault_write_plain_markdown_succeeds(vault_dir):
    """Plain markdown with bullets / numbered lists but no checkboxes writes fine."""
    result = json.loads(vault_write(
        "plain.md",
        "# Heading\n\n- item one\n- item two\n\n1. numbered\n2. numbered\n",
    ))
    assert "error" not in result
    assert result["created"] is True


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
