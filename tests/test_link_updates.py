"""Link rewriting when a note is moved or renamed.

Covers the seam, not just the helper: every test drives `vault_move`, the tool an
MCP client actually calls, so a disconnected wire fails here.
"""

import json

import pytest

from obsidian_vault_mcp import config
from obsidian_vault_mcp.tools.manage import vault_move


@pytest.fixture
def linked_vault(vault_dir):
    """A vault whose notes link to `target.md` in every form we claim to handle."""
    vault = config.VAULT_PATH
    (vault / "target.md").write_text("The note everything points at.\n")
    (vault / "linker.md").write_text(
        "A bare link [[target]].\n"
        "An alias [[target|the target]].\n"
        "A heading [[target#Section]].\n"
        "A block [[target#^abc123]].\n"
        "An embed ![[target]].\n"
        "A path link [[target.md]].\n"
        "A markdown link [see](target.md).\n"
        "Not ours: [[other]], [web](https://example.com/target.md), [[targets]].\n"
    )
    (vault / "subfolder" / "deep.md").write_text(
        "Root-relative [[target]] and markdown [x](../target.md).\n"
    )
    return vault


def _move(source, destination, **kwargs):
    return json.loads(vault_move(source, destination, **kwargs))


def test_rename_repoints_every_link_form(linked_vault):
    result = _move("target.md", "renamed.md")

    assert result["moved"] is True
    body = (linked_vault / "linker.md").read_text()
    assert "[[renamed]]" in body
    assert "[[renamed|the target]]" in body
    assert "[[renamed#Section]]" in body
    assert "[[renamed#^abc123]]" in body
    assert "![[renamed]]" in body
    assert "[see](renamed.md)" in body
    assert "[[target]]" not in body
    assert "[[target|" not in body
    assert "[[target#" not in body
    # Links that were never ours are untouched.
    assert "[[other]]" in body
    assert "[web](https://example.com/target.md)" in body
    assert "[[targets]]" in body
    assert result["links"]["files_updated"] == 2


def test_rename_repoints_links_from_a_subfolder(linked_vault):
    _move("target.md", "renamed.md")

    body = (linked_vault / "subfolder" / "deep.md").read_text()
    assert "[[renamed]]" in body
    assert "../renamed.md" in body


def test_move_without_rename_leaves_basename_links_alone(linked_vault):
    """Obsidian resolves [[target]] by basename, so a pure move must not churn it."""
    (linked_vault / "archive").mkdir()
    result = _move("target.md", "archive/target.md")

    body = (linked_vault / "linker.md").read_text()
    assert "[[target]]" in body
    # The path-shaped references do have to follow the file.
    assert "[see](archive/target.md)" in body
    assert result["links"]["links_updated"] >= 1


def test_ambiguous_basename_is_reported_not_guessed(vault_dir):
    """Two notes share a basename: rewriting would be a guess, so we refuse and say so."""
    vault = config.VAULT_PATH
    (vault / "notes").mkdir()
    (vault / "notes" / "meeting.md").write_text("one\n")
    (vault / "subfolder" / "meeting.md").write_text("two\n")
    (vault / "linker.md").write_text("Ambiguous [[meeting]].\n")

    result = _move("notes/meeting.md", "notes/standup.md")

    assert (vault / "linker.md").read_text() == "Ambiguous [[meeting]].\n"
    assert result["links"]["ambiguous"] == ["meeting"]
    assert result["links"]["files_updated"] == 0


def test_directory_move_repoints_each_note_inside(vault_dir):
    vault = config.VAULT_PATH
    (vault / "projects").mkdir()
    (vault / "projects" / "shed.md").write_text("inside\n")
    (vault / "linker.md").write_text("Path link [[projects/shed]] and bare [[shed]].\n")

    result = _move("projects", "archive")

    body = (linker := vault / "linker.md").read_text()
    assert linker.exists()
    assert "[[archive/shed]]" in body
    # The basename did not change, so the bare link still resolves and stays put.
    assert "[[shed]]" in body
    assert result["links"]["links_updated"] == 1


def test_moved_note_keeps_its_own_links(linked_vault):
    """A note that links to itself is not rewritten out from under itself."""
    (linked_vault / "self.md").write_text("Points at [[self]] and [[target]].\n")
    _move("self.md", "renamed-self.md")

    body = (linked_vault / "renamed-self.md").read_text()
    assert body == "Points at [[self]] and [[target]].\n"


def test_unreadable_file_is_skipped_not_mangled(linked_vault):
    """A file we cannot decode is a file we must not rewrite."""
    (linked_vault / "binary.md").write_bytes(b"\xff\xfe not utf 8 [[target]]\n")

    result = _move("target.md", "renamed.md")

    assert (linked_vault / "binary.md").read_bytes().startswith(b"\xff\xfe")
    assert "binary.md" not in result["links"]["files"]


def test_oversized_file_is_skipped(linked_vault, monkeypatch):
    monkeypatch.setattr(config, "MAX_CONTENT_SIZE", 50)
    big = "x" * 100 + " [[target]]\n"
    (linked_vault / "big.md").write_text(big)

    result = _move("target.md", "renamed.md")

    assert (linked_vault / "big.md").read_text() == big
    assert "big.md" not in result["links"]["files"]


def test_excluded_directories_are_never_rewritten(linked_vault):
    trash = config.VAULT_PATH / ".trash"
    trash.mkdir(exist_ok=True)
    (trash / "old.md").write_text("Deleted note linking [[target]].\n")

    _move("target.md", "renamed.md")

    assert "[[target]]" in (trash / "old.md").read_text()


def test_failed_move_rewrites_nothing(linked_vault):
    """The destination already exists: nothing moved, so no link may change."""
    result = _move("target.md", "linker.md")

    assert "error" in result
    assert "[[target]]" in (linked_vault / "linker.md").read_text()


def test_path_traversal_in_source_is_refused(linked_vault):
    result = _move("../outside.md", "renamed.md")

    assert "error" in result
    assert "[[target]]" in (linked_vault / "linker.md").read_text()
