"""vault_write's create-only mode: overwrite=false never replaces an existing file.

The default stays overwrite=true, so every existing call behaves as before.
overwrite=false is for a note that must not exist yet: a task filed by an automated
client, a retry after a lost response, two sessions picking the same name. It is the
same no-clobber placement vault_write_binary already uses (os.link), so the check and
the creation are one step and a concurrent writer cannot slip in between.

Every case goes through the registered tool, like test_vault_edit_replace_all.py.
"""

import asyncio
import json
import threading

import pytest

from obsidian_vault_mcp import server, write_events


def call_tool(name: str, arguments: dict) -> dict:
    result = asyncio.run(server.mcp.call_tool(name, arguments))
    if isinstance(result, tuple):
        result = result[0]
    return json.loads("".join(getattr(block, "text", "") for block in result))


@pytest.fixture
def events():
    captured = []
    write_events.register_write_listener(lambda op, paths: captured.append((op, paths)))
    yield captured
    write_events._write_listeners.clear()


def test_the_default_still_replaces(vault_dir):
    """Negative control: without the flag an existing file is replaced, as before."""
    (vault_dir / "n.md").write_bytes(b"alt\n")

    result = call_tool("vault_write", {"path": "n.md", "content": "neu\n"})

    assert result.get("created") is False and "error" not in result, result
    assert (vault_dir / "n.md").read_bytes().startswith(b"neu")


def test_create_only_creates_a_new_file(vault_dir, events):
    result = call_tool("vault_write", {"path": "neu/n.md", "content": "x\n", "overwrite": False})

    assert result.get("created") is True, result
    assert (vault_dir / "neu" / "n.md").exists()
    assert events == [("created", ["neu/n.md"])]


def test_create_only_leaves_an_existing_file_untouched(vault_dir, events):
    (vault_dir / "n.md").write_bytes(b"alt\n")

    result = call_tool("vault_write", {"path": "n.md", "content": "neu\n", "overwrite": False})

    assert "already exists" in result.get("error", ""), result
    assert result["created"] is False
    assert (vault_dir / "n.md").read_bytes() == b"alt\n"
    assert events == []
    assert not [p for p in vault_dir.iterdir() if p.name.endswith(".tmp")]


def test_a_retry_after_a_lost_response_does_not_replace(vault_dir):
    first = call_tool("vault_write", {"path": "n.md", "content": "eins\n", "overwrite": False})
    again = call_tool("vault_write", {"path": "n.md", "content": "zwei\n", "overwrite": False})

    assert first.get("created") is True and "already exists" in again.get("error", ""), (first, again)
    assert (vault_dir / "n.md").read_bytes().startswith(b"eins")


def test_two_racing_calls_create_exactly_once(vault_dir):
    barrier = threading.Barrier(2)
    results = []

    def writer(text):
        barrier.wait()
        results.append(call_tool("vault_write", {"path": "race.md", "content": text, "overwrite": False}))

    threads = [threading.Thread(target=writer, args=(f"writer {i}\n",)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    created = [r for r in results if r.get("created") is True]
    refused = [r for r in results if "already exists" in r.get("error", "")]
    assert len(created) == 1 and len(refused) == 1, results
    assert (vault_dir / "race.md").read_text(encoding="utf-8").startswith("writer ")


def test_create_only_and_merge_frontmatter_are_refused_together(vault_dir):
    result = call_tool(
        "vault_write", {"path": "n.md", "content": "---\na: 1\n---\n", "overwrite": False, "merge_frontmatter": True}
    )

    assert "merge_frontmatter" in result.get("error", ""), result
    assert not (vault_dir / "n.md").exists()
