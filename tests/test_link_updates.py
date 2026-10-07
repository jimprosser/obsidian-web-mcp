"""Link rewriting when a note is moved or renamed.

Covers the seam, not just the helper: every test drives `vault_move`, the tool an
MCP client actually calls, so a disconnected wire fails here.
"""

import json
import os

import pytest

from obsidian_vault_mcp import config, links, server
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


# --- the walk honors the read guards (#79) --------------------------------------


def test_hardlinked_file_is_skipped(linked_vault, tmp_path_factory):
    """A hardlink's other name may sit outside the vault. Rewriting it would replace
    the link with an ordinary vault file holding the outside content, which the read
    tools would then serve in full."""
    outside = tmp_path_factory.mktemp("outside") / "secret.md"
    outside.write_text("Outside the vault, links [[target]].\n")
    inside = linked_vault / "notes.md"
    os.link(outside, inside)

    result = _move("target.md", "renamed.md")

    assert inside.stat().st_nlink == 2
    assert inside.stat().st_ino == outside.stat().st_ino
    assert outside.read_text() == "Outside the vault, links [[target]].\n"
    assert "notes.md" not in result["links"]["files"]
    # The rest of the pass still ran.
    assert "[[renamed]]" in (linked_vault / "linker.md").read_text()


def test_symlinked_file_is_skipped(linked_vault, tmp_path_factory):
    """A symlink whose target is outside the vault is neither followed nor replaced,
    and it doesn't stop the files after it from being rewritten."""
    outside = tmp_path_factory.mktemp("outside") / "secret.md"
    outside.write_text("Outside the vault, links [[target]].\n")
    inside = linked_vault / "aaa-link.md"
    inside.symlink_to(outside)

    result = _move("target.md", "renamed.md")

    assert inside.is_symlink()
    assert outside.read_text() == "Outside the vault, links [[target]].\n"
    assert "aaa-link.md" not in result["links"]["files"]
    assert result["links"]["failed"] == []
    assert sorted(result["links"]["files"]) == ["linker.md", "subfolder/deep.md"]


def test_symlink_inside_the_vault_is_skipped(linked_vault):
    """An in-vault symlink is skipped too. Followed, it would carry the rewrite into
    places the walk never goes, such as .trash."""
    trash = linked_vault / ".trash"
    trash.mkdir(exist_ok=True)
    (trash / "old.md").write_text("Deleted note linking [[target]].\n")
    (linked_vault / "alias.md").symlink_to(trash / "old.md")

    result = _move("target.md", "renamed.md")

    assert (trash / "old.md").read_text() == "Deleted note linking [[target]].\n"
    assert "alias.md" not in result["links"]["files"]


# --- one bad file costs one file -------------------------------------------------


def test_one_failed_write_costs_one_file(linked_vault, monkeypatch):
    real_write = links.write_file_atomic

    def flaky_write(rel, content, **kwargs):
        if rel == "linker.md":
            raise OSError("disk said no")
        return real_write(rel, content, **kwargs)

    monkeypatch.setattr(links, "write_file_atomic", flaky_write)

    result = _move("target.md", "renamed.md")

    assert result["moved"] is True
    assert result["links"]["failed"] == [{"path": "linker.md", "error": "disk said no"}]
    assert result["links"]["files"] == ["subfolder/deep.md"]
    assert result["links"]["files_updated"] == 1
    assert "[[renamed]]" in (linked_vault / "subfolder" / "deep.md").read_text()
    assert "[[target]]" in (linked_vault / "linker.md").read_text()


# --- dry_run ---------------------------------------------------------------------


def _snapshot(vault):
    return {
        p.relative_to(vault).as_posix(): p.read_bytes()
        for p in vault.rglob("*")
        if p.is_file()
    }


def test_dry_run_moves_and_writes_nothing(linked_vault):
    before = _snapshot(linked_vault)

    result = _move("target.md", "renamed.md", dry_run=True)

    assert _snapshot(linked_vault) == before
    assert result["moved"] is False
    assert result["dry_run"] is True
    links_summary = result["links"]
    assert sorted(links_summary["files"]) == ["linker.md", "subfolder/deep.md"]
    assert sorted(links_summary["diffs"]) == ["linker.md", "subfolder/deep.md"]
    diff = links_summary["diffs"]["linker.md"]
    assert "-A bare link [[target]]." in diff
    assert "+A bare link [[renamed]]." in diff
    assert "+A markdown link [see](renamed.md)." in diff


@pytest.mark.parametrize(
    "source, destination",
    [
        ("target.md", "renamed.md"),
        ("target.md", "archive/target.md"),
        ("projects", "archive/projects"),
    ],
)
def test_dry_run_predicts_the_real_move(linked_vault, source, destination):
    vault = linked_vault
    (vault / "projects").mkdir()
    (vault / "projects" / "shed.md").write_text("Links [[target]] and [[projects/barn]].\n")
    (vault / "projects" / "barn.md").write_text("barn\n")
    (vault / "plans.md").write_text("[[projects/shed]] [s](projects/shed.md) [[shed]]\n")

    preview = _move(source, destination, dry_run=True)
    real = _move(source, destination)

    expected = {k: v for k, v in preview["links"].items() if k != "diffs"}
    assert expected == real["links"]
    assert preview["links"]["files"], "the case should rewrite something"


def test_dry_run_of_a_move_that_would_fail_reports_the_error(linked_vault):
    before = _snapshot(linked_vault)

    result = _move("target.md", "linker.md", dry_run=True)

    assert "Destination already exists" in result["error"]
    assert _snapshot(linked_vault) == before


def test_dry_run_reaches_the_registered_tool(linked_vault):
    """The parameter is wired through the server tool and its input model."""
    before = _snapshot(linked_vault)

    result = json.loads(server.vault_move("target.md", "renamed.md", dry_run=True))

    assert result["dry_run"] is True
    assert "linker.md" in result["links"]["diffs"]
    assert _snapshot(linked_vault) == before
