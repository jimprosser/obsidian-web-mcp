"""Link rewriting when a note is moved or renamed.

Covers the seam, not just the helper: every test drives `vault_move`, the tool an
MCP client actually calls, so a disconnected wire fails here.
"""

import asyncio
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


def test_renamed_note_repoints_its_own_self_links(linked_vault):
    """#110: a self-link follows the rename, the way Obsidian rewrites it."""
    (linked_vault / "self.md").write_text(
        "Points at [[self]], [[self#Top]], [me](self.md) and [[target]].\n"
    )

    result = _move("self.md", "renamed-self.md")

    body = (linked_vault / "renamed-self.md").read_text()
    assert body == (
        "Points at [[renamed-self]], [[renamed-self#Top]], [me](renamed-self.md) and [[target]].\n"
    )
    assert "renamed-self.md" in result["links"]["files"]


def test_moved_note_keeps_its_relative_links_resolving(vault_dir):
    """#110: a move to another depth re-expresses the note's relative links from its new
    folder, and leaves alone every link whose reading is not clear."""
    vault = config.VAULT_PATH
    (vault / "notes" / "archive").mkdir(parents=True)
    (vault / "assets").mkdir()
    (vault / "assets" / "pic.png").write_bytes(b"png")
    for name in ("b.md", "both.md", "notes/sibling.md", "notes/both.md"):
        (vault / name).write_text("x\n")
    (vault / "notes" / "a.md").write_text(
        "[b](../b.md) [s](sibling.md) [s2](./sibling.md#Part) ![p](../assets/pic.png)\n"
        "[root](b.md) [either](both.md) [gone](../missing.md) [web](https://x.example/b.md)\n"
    )

    result = _move("notes/a.md", "notes/archive/a.md")

    assert (vault / "notes" / "archive" / "a.md").read_text() == (
        "[b](../../b.md) [s](../sibling.md) [s2](../sibling.md#Part) ![p](../../assets/pic.png)\n"
        "[root](b.md) [either](both.md) [gone](../missing.md) [web](https://x.example/b.md)\n"
    )
    assert result["links"]["files"] == ["notes/archive/a.md"]
    assert result["links"]["links_updated"] == 4


def test_directory_move_keeps_inner_notes_linked(vault_dir):
    """#110: notes inside a moved folder keep their links to each other and to the
    files that moved with them, and their links out of the folder follow the new place."""
    vault = config.VAULT_PATH
    (vault / "notes" / "proj").mkdir(parents=True)
    (vault / "archive").mkdir()
    (vault / "notes" / "b.md").write_text("x\n")
    (vault / "notes" / "proj" / "s.md").write_text("x\n")
    (vault / "notes" / "proj" / "p.png").write_bytes(b"png")
    (vault / "notes" / "proj" / "a.md").write_text(
        "[[notes/proj/s]] [[s]] [s](s.md) ![p](p.png) [b](../b.md)\n"
    )

    result = _move("notes/proj", "archive/proj")

    assert (vault / "archive" / "proj" / "a.md").read_text() == (
        "[[archive/proj/s]] [[s]] [s](s.md) ![p](p.png) [b](../../notes/b.md)\n"
    )
    assert result["links"]["files"] == ["archive/proj/a.md"]
    assert result["links"]["links_updated"] == 2


def test_explicit_relative_link_is_not_read_from_the_root(vault_dir):
    """`./p/b.md` in `p/a.md` names `p/p/b.md`, never the root reading `p/b.md`."""
    vault = config.VAULT_PATH
    (vault / "p" / "p").mkdir(parents=True)
    (vault / "archive").mkdir()
    (vault / "p" / "b.md").write_text("x\n")
    (vault / "p" / "p" / "b.md").write_text("x\n")
    (vault / "p" / "a.md").write_text("[b](./p/b.md) [sib](./b.md)\n")

    result = _move("p", "archive/p")

    assert (vault / "archive" / "p" / "a.md").read_text() == "[b](./p/b.md) [sib](./b.md)\n"
    assert result["links"]["links_updated"] == 0


def test_explicit_relative_link_in_a_note_that_stays_put(vault_dir):
    """The same rule for a note that did not move: `./p/b.md` in `p/x.md` is not `p/b.md`."""
    vault = config.VAULT_PATH
    (vault / "p" / "p").mkdir(parents=True)
    (vault / "p" / "b.md").write_text("x\n")
    (vault / "p" / "p" / "b.md").write_text("x\n")
    (vault / "p" / "x.md").write_text("[b](./p/b.md) [moved](./b.md) [rooted](/./p/b.md)\n")

    _move("p/b.md", "p/c.md")

    assert (vault / "p" / "x.md").read_text() == (
        "[b](./p/b.md) [moved](./c.md) [rooted](p/c.md)\n"
    )


def test_link_above_the_vault_root_is_left_alone(vault_dir):
    vault = config.VAULT_PATH
    (vault / "notes").mkdir()
    (vault / "b.md").write_text("x\n")
    (vault / "notes" / "a.md").write_text("[out](../../b.md)\n")

    _move("notes/a.md", "a.md")

    assert (vault / "a.md").read_text() == "[out](../../b.md)\n"


def test_a_note_differing_only_in_case_is_not_the_moved_one(vault_dir):
    vault = config.VAULT_PATH
    (vault / "b").mkdir()
    (vault / "b" / "a.md").write_text("![x](./x.png)\n")
    if (vault / "b" / "A.md").exists():
        pytest.skip("case-insensitive filesystem")
    (vault / "b" / "x.png").write_bytes(b"png")
    # Read from the root note's folder, `./x.png` would name this one instead.
    (vault / "x.png").write_bytes(b"png")
    (vault / "a.md").write_text("root\n")

    result = _move("a.md", "b/A.md")

    assert (vault / "b" / "a.md").read_text() == "![x](./x.png)\n"
    assert "b/a.md" not in result["links"]["files"]


def test_dry_run_shows_the_moved_note_under_its_new_path(linked_vault):
    (linked_vault / "subfolder" / "self.md").write_text("[[self]] [t](../target.md)\n")

    preview = _move("subfolder/self.md", "subfolder/deeper/renamed.md", dry_run=True)
    real = _move("subfolder/self.md", "subfolder/deeper/renamed.md")

    assert list(preview["links"]["diffs"]) == ["subfolder/deeper/renamed.md"]
    assert "+[[renamed]] [t](../../target.md)" in preview["links"]["diffs"]["subfolder/deeper/renamed.md"]
    assert {k: v for k, v in preview["links"].items() if k != "diffs"} == real["links"]


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
        ("./target.md", "./renamed.md"),
        ("projects/", "archive/projects/"),
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


def test_dot_slash_paths_match_like_plain_ones(linked_vault):
    """`./target.md` passes the path guard, so it must match links the same way
    `target.md` does, in the real move and in the dry run."""
    preview = _move("./target.md", "./renamed.md", dry_run=True)
    assert "+A markdown link [see](renamed.md)." in preview["links"]["diffs"]["linker.md"]

    _move("./target.md", "./renamed.md")
    assert "[see](renamed.md)" in (linked_vault / "linker.md").read_text()


def test_dry_run_predicts_a_write_that_would_fail(linked_vault, monkeypatch):
    """A rename to a longer name can push a file past the size limit. The real move
    reports that file as failed, so the preview must too."""
    monkeypatch.setattr(config, "MAX_CONTENT_SIZE", (linked_vault / "linker.md").stat().st_size)

    preview = _move("target.md", "a-much-longer-name.md", dry_run=True)
    real = _move("target.md", "a-much-longer-name.md")

    assert [f["path"] for f in preview["links"]["failed"]] == ["linker.md"]
    assert "linker.md" not in preview["links"]["diffs"]
    expected = {k: v for k, v in preview["links"].items() if k != "diffs"}
    assert expected == real["links"]


@pytest.mark.parametrize(
    "source, destination, kwargs, message",
    [
        ("target.md", "linker.md", {}, "Destination already exists"),
        ("target.md", "missing/renamed.md", {"create_dirs": False}, "Destination directory does not exist"),
        ("subfolder", "subfolder/inner", {}, "Cannot move a directory into itself"),
    ],
)
def test_dry_run_refuses_what_the_move_would_refuse(linked_vault, source, destination, kwargs, message):
    before = _snapshot(linked_vault)

    preview = _move(source, destination, dry_run=True, **kwargs)

    assert message in preview["error"]
    assert _snapshot(linked_vault) == before
    assert "error" in _move(source, destination, **kwargs)
    assert _snapshot(linked_vault) == before


def test_dry_run_reaches_the_registered_tool(linked_vault):
    """The parameter is wired through the registered tool and its input model."""
    before = _snapshot(linked_vault)

    result = asyncio.run(
        server.mcp.call_tool("vault_move", {"source": "target.md", "destination": "renamed.md", "dry_run": True})
    )
    if isinstance(result, tuple):
        result = result[0]
    result = json.loads("".join(getattr(block, "text", "") for block in result))

    assert result["dry_run"] is True
    assert "linker.md" in result["links"]["diffs"]
    assert _snapshot(linked_vault) == before
