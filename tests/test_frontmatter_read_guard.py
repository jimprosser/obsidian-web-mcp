"""vault_search_frontmatter returns only what vault_read would read.

The frontmatter index parsed every .md file under the vault, following symlinks and
hardlinks, so a symlink pointing out of the vault or a hardlink exposed its frontmatter
through vault_search_frontmatter while vault_read refused the same path.
"""

import asyncio
import json
import os

import pytest

from obsidian_vault_mcp import config, server


def _search(field: str) -> list[str]:
    result = asyncio.run(server.mcp.call_tool(
        "vault_search_frontmatter", {"field": field, "match_type": "exists"}
    ))
    if isinstance(result, tuple):
        result = result[0]
    payload = json.loads("".join(getattr(block, "text", "") for block in result))
    return sorted(hit["path"] for hit in payload["results"])


def _flush(paths):
    """Hand paths to the watcher's flush, as a debounced change event would."""
    index = server.frontmatter_index
    for rel in paths:
        index._pending_paths.add(str(config.VAULT_PATH / rel))
    index._flush_pending()


@pytest.fixture
def outside(tmp_path):
    folder = tmp_path / "outside"
    folder.mkdir()
    (folder / "secret.md").write_text("---\nleak: symlinked\n---\n")
    (folder / "other.md").write_text("---\nleak: hardlinked\n---\n")
    return folder


@pytest.mark.parametrize("via", ["rebuild", "watcher"])
def test_symlinks_and_hardlinks_are_not_indexed(vault_dir, outside, via):
    server.frontmatter_index.rebuild()  # the vault before the files below exist
    (vault_dir / "own.md").write_text("---\nleak: own note\n---\n")
    (vault_dir / "link.md").symlink_to(outside / "secret.md")
    os.link(outside / "other.md", vault_dir / "hard.md")
    (vault_dir / "loop-a.md").symlink_to(vault_dir / "loop-b.md")
    (vault_dir / "loop-b.md").symlink_to(vault_dir / "loop-a.md")

    if via == "rebuild":
        server.frontmatter_index.rebuild()
    else:
        _flush(["own.md", "link.md", "hard.md", "loop-a.md", "loop-b.md"])

    assert _search("leak") == ["own.md"]


def test_a_note_that_becomes_a_hardlink_leaves_the_index(vault_dir, tmp_path):
    note = vault_dir / "note.md"
    note.write_text("---\nleak: was readable\n---\n")
    server.frontmatter_index.rebuild()
    assert _search("leak") == ["note.md"]

    os.link(note, tmp_path / "second-name.md")
    _flush(["note.md"])

    assert _search("leak") == []
