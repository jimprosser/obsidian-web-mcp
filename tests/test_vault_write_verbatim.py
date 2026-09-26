"""vault_write writes content byte for byte (#99).

VaultWriteInput stripped surrounding whitespace from every string field, content
included: '    indented\\n\\nlast\\n' reached the disk as 'indented\\n\\nlast'. Every note
written through a connector lost its trailing newline, and a note starting with an
indented line lost the indent. Paths are still normalised.

Every case goes through the registered tool, and covers each way vault_write writes:
create, replace, create-only (#101) and merge_frontmatter.
"""

import asyncio
import json

import pytest

from obsidian_vault_mcp import server

CONTENT = "    indented first line\n\nlast line\n\n"


def call_tool(name: str, arguments: dict) -> dict:
    result = asyncio.run(server.mcp.call_tool(name, arguments))
    if isinstance(result, tuple):
        result = result[0]
    return json.loads("".join(getattr(block, "text", "") for block in result))


@pytest.mark.parametrize("extra", [{}, {"overwrite": False}], ids=["create", "create-only"])
def test_a_new_file_gets_the_exact_bytes(vault_dir, extra):
    result = call_tool("vault_write", {"path": "n.md", "content": CONTENT, **extra})

    assert result.get("created") is True, result
    assert (vault_dir / "n.md").read_bytes() == CONTENT.encode("utf-8")


def test_a_replaced_file_gets_the_exact_bytes(vault_dir):
    (vault_dir / "n.md").write_bytes(b"old\n")

    result = call_tool("vault_write", {"path": "n.md", "content": CONTENT})

    assert result.get("created") is False, result
    assert (vault_dir / "n.md").read_bytes() == CONTENT.encode("utf-8")


def test_a_frontmatter_merge_keeps_the_body_exactly(vault_dir):
    (vault_dir / "n.md").write_text("---\na: 1\n---\nold body\n", encoding="utf-8")
    body = "\n    code line\n\ntext\n"

    call_tool("vault_write", {"path": "n.md", "content": "---\nb: 2\n---\n" + body, "merge_frontmatter": True})

    written = (vault_dir / "n.md").read_text(encoding="utf-8")
    assert written.endswith(body), repr(written)
    assert "a: 1" in written and "b: 2" in written


def test_paths_are_still_normalised(vault_dir):
    """Guard: the fix is per field; the path keeps its stripping."""
    result = call_tool("vault_write", {"path": "  n.md  ", "content": "x\n"})

    assert result.get("path") == "n.md", result
    assert (vault_dir / "n.md").exists()
