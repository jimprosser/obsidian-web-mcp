"""Integration tests for tool functions."""

import json

import pytest

from obsidian_vault_mcp.tools.read import vault_read, vault_batch_read
from obsidian_vault_mcp.tools.write import vault_write, vault_batch_frontmatter_update, vault_patch, vault_append
from obsidian_vault_mcp.tools.search import vault_search, vault_search_frontmatter
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


def test_date_frontmatter_serializes(vault_dir):
    """Frontmatter with unquoted ISO date (parsed as datetime.date by PyYAML)
    must not raise TypeError during JSON serialization."""
    # unquoted date — PyYAML converts to datetime.date
    (vault_dir / "dated-unquoted.md").write_text(
        "---\ndata: 2026-01-24\ntitle: Dated\n---\n\nConteudo com data.\n"
    )
    # quoted date — stays as str, must also work
    (vault_dir / "dated-quoted.md").write_text(
        '---\ndata: "2026-01-24"\ntitle: Dated Quoted\n---\n\nConteudo com data.\n'
    )

    # vault_read — unquoted
    result = json.loads(vault_read("dated-unquoted.md"))
    assert "error" not in result
    assert result["frontmatter"]["data"] == "2026-01-24"

    # vault_read — quoted
    result = json.loads(vault_read("dated-quoted.md"))
    assert "error" not in result
    assert result["frontmatter"]["data"] == "2026-01-24"

    # vault_batch_read
    result = json.loads(vault_batch_read(["dated-unquoted.md", "dated-quoted.md"]))
    assert result["found"] == 2
    assert result["missing"] == 0
    for f in result["files"]:
        assert "error" not in f
        assert f["frontmatter"]["data"] == "2026-01-24"

    # vault_search — frontmatter_excerpt is injected into results
    result = json.loads(vault_search("Conteudo com data"))
    assert "error" not in result
    # just confirming no serialization error; result may have 1 or 2 hits
    assert result["total_matches"] >= 1


# --- vault_patch tests ---

def test_vault_patch_replaces_unique_string(vault_dir):
    """vault_patch replaces a string that appears exactly once."""
    vault_write("patch-test.md", "# Title\n\nOld content here.\n\nMore text.")
    result = json.loads(vault_patch("patch-test.md", "Old content here.", "New content here."))
    assert "error" not in result
    assert result["replacements"] == 1
    read_result = json.loads(vault_read("patch-test.md"))
    assert "New content here." in read_result["content"]
    assert "Old content here." not in read_result["content"]


def test_vault_patch_fails_on_no_match(vault_dir):
    """vault_patch returns error when old_string is not found."""
    vault_write("patch-test2.md", "# Title\n\nSome content.")
    result = json.loads(vault_patch("patch-test2.md", "nonexistent string", "replacement"))
    assert "error" in result
    assert "0 occurrences" in result["error"]


def test_vault_patch_fails_on_multiple_matches(vault_dir):
    """vault_patch returns error when old_string appears more than once."""
    vault_write("patch-test3.md", "repeat repeat repeat")
    result = json.loads(vault_patch("patch-test3.md", "repeat", "once"))
    assert "error" in result
    assert "3 occurrences" in result["error"]


def test_vault_patch_replace_all(vault_dir):
    """vault_patch with replace_all=True replaces every occurrence."""
    vault_write("patch-test4.md", "a b a b a")
    result = json.loads(vault_patch("patch-test4.md", "a", "x", replace_all=True))
    assert "error" not in result
    assert result["replacements"] == 3
    read_result = json.loads(vault_read("patch-test4.md"))
    assert read_result["content"] == "x b x b x"


def test_vault_patch_file_not_found(vault_dir):
    """vault_patch returns error for nonexistent file."""
    result = json.loads(vault_patch("does-not-exist.md", "old", "new"))
    assert "error" in result


# --- vault_append tests ---

def test_vault_append_adds_to_existing(vault_dir):
    """vault_append adds content after existing file body."""
    vault_write("append-test.md", "# Log\n\nFirst entry.")
    result = json.loads(vault_append("append-test.md", "Second entry."))
    assert "error" not in result
    assert result["created"] is False
    read_result = json.loads(vault_read("append-test.md"))
    assert "First entry." in read_result["content"]
    assert "Second entry." in read_result["content"]
    assert read_result["content"].index("First entry.") < read_result["content"].index("Second entry.")


def test_vault_append_creates_new_file(vault_dir):
    """vault_append creates the file if it does not exist."""
    result = json.loads(vault_append("new-append.md", "Initial content."))
    assert "error" not in result
    assert result["created"] is True
    assert (vault_dir / "new-append.md").exists()
    read_result = json.loads(vault_read("new-append.md"))
    assert "Initial content." in read_result["content"]


def test_vault_append_custom_separator(vault_dir):
    """vault_append respects a custom separator."""
    vault_write("sep-test.md", "line one")
    result = json.loads(vault_append("sep-test.md", "line two", separator="\n\n---\n\n"))
    assert "error" not in result
    read_result = json.loads(vault_read("sep-test.md"))
    assert "line one\n\n---\n\nline two" in read_result["content"]


def test_vault_append_no_double_separator(vault_dir):
    """vault_append on a new file does not prepend the separator."""
    result = json.loads(vault_append("fresh.md", "content", separator="\n\n"))
    assert "error" not in result
    read_result = json.loads(vault_read("fresh.md"))
    assert read_result["content"] == "content"
