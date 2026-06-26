"""Tests for vault_search context_lines behavior across both search backends.

Regression coverage for the bug where the ripgrep backend passed --context to
rg but discarded the resulting context events, so context_lines was a no-op on
the ripgrep path while the Python fallback honored it. The two backends must
return identical match_context for the same query.
"""

import json
import os
import shutil
from types import SimpleNamespace

import pytest

import obsidian_vault_mcp.tools.search as search_mod
from obsidian_vault_mcp.tools.search import vault_search

RG_AVAILABLE = shutil.which("rg") is not None
requires_rg = pytest.mark.skipif(not RG_AVAILABLE, reason="ripgrep not installed")


def _rg_match_json(path, line_number, text):
    """One ripgrep --json "match" event line, as _search_ripgrep parses it.

    Used by the re-read hardening tests to make ripgrep "report" a chosen path
    (e.g. a symlink) without the real binary, which never follows symlinks.
    """
    return (
        json.dumps(
            {
                "type": "match",
                "data": {
                    "path": {"text": str(path)},
                    "line_number": line_number,
                    "lines": {"text": text},
                },
            }
        )
        + "\n"
    )

# A file with a known, stable line layout so we can assert exact slices.
SAMPLE = (
    "alpha one\n"
    "beta two\n"
    "TARGET middle\n"
    "gamma four\n"
    "delta five\n"
)


def _force_backend(monkeypatch, backend):
    """Force vault_search down a specific backend by faking shutil.which.

    vault_search only uses shutil.which("rg") as a truthiness check to choose a
    backend; _search_ripgrep then runs the bare "rg" command resolved from PATH.
    So the faked return value only needs to be falsy (Python) or truthy
    (ripgrep), not a real binary path.
    """
    if backend == "python":
        monkeypatch.setattr(search_mod.shutil, "which", lambda _name: None)
    elif backend == "ripgrep":
        monkeypatch.setattr(search_mod.shutil, "which", lambda _name: "rg")
    else:
        raise ValueError(backend)


def _search(monkeypatch, backend, vault_dir, query, **kwargs):
    (vault_dir / "sample.md").write_text(SAMPLE)
    _force_backend(monkeypatch, backend)
    result = json.loads(vault_search(query, file_pattern="sample.md", **kwargs))
    return result["results"]


@requires_rg
def test_ripgrep_honors_context_lines(monkeypatch, vault_dir):
    results = _search(monkeypatch, "ripgrep", vault_dir, "TARGET", context_lines=1)
    assert len(results) == 1
    assert results[0]["match_context"] == "beta two\nTARGET middle\ngamma four"


def test_python_honors_context_lines(monkeypatch, vault_dir):
    results = _search(monkeypatch, "python", vault_dir, "TARGET", context_lines=1)
    assert len(results) == 1
    assert results[0]["match_context"] == "beta two\nTARGET middle\ngamma four"


@requires_rg
def test_backends_produce_identical_context(monkeypatch, vault_dir):
    rg = _search(monkeypatch, "ripgrep", vault_dir, "TARGET", context_lines=2)
    py = _search(monkeypatch, "python", vault_dir, "TARGET", context_lines=2)
    assert [m["match_context"] for m in rg] == [m["match_context"] for m in py]
    assert rg[0]["match_context"] == (
        "alpha one\nbeta two\nTARGET middle\ngamma four\ndelta five"
    )


@requires_rg
def test_ripgrep_context_lines_zero_returns_only_match(monkeypatch, vault_dir):
    results = _search(monkeypatch, "ripgrep", vault_dir, "TARGET", context_lines=0)
    assert results[0]["match_context"] == "TARGET middle"


@requires_rg
def test_ripgrep_context_clamps_at_first_line(monkeypatch, vault_dir):
    results = _search(monkeypatch, "ripgrep", vault_dir, "alpha", context_lines=2)
    assert results[0]["match_context"] == "alpha one\nbeta two\nTARGET middle"


@requires_rg
def test_ripgrep_context_clamps_at_last_line(monkeypatch, vault_dir):
    results = _search(monkeypatch, "ripgrep", vault_dir, "delta", context_lines=2)
    assert results[0]["match_context"] == "TARGET middle\ngamma four\ndelta five"


@requires_rg
def test_ripgrep_multiple_matches_in_one_file(monkeypatch, vault_dir):
    """Two matches in the same file must each get their own correct context
    (exercises the per-file read cache)."""
    (vault_dir / "multi.md").write_text(
        "intro\nhit one\nmid\nhit two\nend\n"
    )
    _force_backend(monkeypatch, "ripgrep")
    results = json.loads(
        vault_search("hit", file_pattern="multi.md", context_lines=1)
    )["results"]
    assert len(results) == 2
    assert results[0]["match_context"] == "intro\nhit one\nmid"
    assert results[1]["match_context"] == "mid\nhit two\nend"


@requires_rg
def test_ripgrep_falls_back_to_match_line_when_reread_fails(monkeypatch, vault_dir):
    """If the matched file cannot be re-read, the ripgrep backend degrades to
    the matched line itself, not an empty string."""
    (vault_dir / "sample.md").write_text(SAMPLE)
    _force_backend(monkeypatch, "ripgrep")

    real_open = os.open

    def failing_open(path, flags, *args, **kwargs):
        if str(path).endswith("sample.md"):
            raise OSError("simulated read failure")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(search_mod.os, "open", failing_open)

    results = json.loads(
        vault_search("delta", file_pattern="sample.md", context_lines=2)
    )["results"]
    assert len(results) == 1
    assert results[0]["match_context"] == "delta five"


@requires_rg
def test_backends_agree_on_count_and_truncated_across_files(monkeypatch, vault_dir):
    """rg's --max-count is per-file, but the global result cap is enforced by
    the loop break, so both backends report the same total_matches and
    truncated flag for a multi-file search that exceeds max_results."""
    (vault_dir / "a.md").write_text("hit a0\nhit a1\nhit a2\n")
    (vault_dir / "b.md").write_text(
        "\n".join(f"hit b{i}" for i in range(10)) + "\n"
    )

    def run(backend):
        _force_backend(monkeypatch, backend)
        return json.loads(vault_search("hit", file_pattern="*.md", max_results=5))

    rg = run("ripgrep")
    py = run("python")
    assert rg["total_matches"] == py["total_matches"] == 5
    assert rg["truncated"] is py["truncated"] is True


@requires_rg
def test_backends_agree_on_unicode_line_separators(monkeypatch, vault_dir):
    """U+2028 is a line break for str.splitlines() but ripgrep counts lines by
    \\n only. Re-reading with splitlines() would desync the index from rg's
    line_number; both backends must still center the matched line and agree."""
    (vault_dir / "u.md").write_text(
        "alpha\u2028beta\nTARGET line\ngamma\ndelta\n"
    )

    def run(backend):
        _force_backend(monkeypatch, backend)
        return json.loads(
            vault_search("TARGET", file_pattern="u.md", context_lines=1)
        )["results"]

    rg = run("ripgrep")
    py = run("python")
    assert len(rg) == 1
    assert rg[0]["match_context"] == "alpha\u2028beta\nTARGET line\ngamma"
    assert rg[0]["match_context"] == py[0]["match_context"]


@requires_rg
def test_backends_agree_on_lone_carriage_return(monkeypatch, vault_dir):
    """A bare \\r is not a line break for ripgrep (it counts \\n only). The
    re-read must not let universal-newline translation turn it into one, or the
    index would desync from rg's line_number."""
    (vault_dir / "cr.md").write_bytes(
        b"a\rb\nTARGET line\ngamma\ndelta\n"
    )

    def run(backend):
        _force_backend(monkeypatch, backend)
        return json.loads(
            vault_search("TARGET", file_pattern="cr.md", context_lines=1)
        )["results"]

    rg = run("ripgrep")
    py = run("python")
    assert len(rg) == 1
    assert rg[0]["match_context"] == "a\rb\nTARGET line\ngamma"
    assert rg[0]["match_context"] == py[0]["match_context"]


@requires_rg
def test_backends_agree_on_crlf(monkeypatch, vault_dir):
    """CRLF files: the trailing \\r is stripped so snippets match str.splitlines
    output, and both backends agree."""
    (vault_dir / "crlf.md").write_bytes(
        b"alpha\r\nTARGET line\r\ngamma\r\n"
    )

    def run(backend):
        _force_backend(monkeypatch, backend)
        return json.loads(
            vault_search("TARGET", file_pattern="crlf.md", context_lines=1)
        )["results"]

    rg = run("ripgrep")
    py = run("python")
    assert len(rg) == 1
    assert "\r" not in rg[0]["match_context"]
    assert rg[0]["match_context"] == "alpha\nTARGET line\ngamma"
    assert rg[0]["match_context"] == py[0]["match_context"]


@requires_rg
def test_ripgrep_non_utf8_match_is_not_empty(monkeypatch, vault_dir):
    """When ripgrep matches a line with invalid UTF-8 (emitted as base64 bytes,
    not text) and the whole-file re-read fails to decode, the match_context
    must still carry the matched line, not collapse to an empty string."""
    (vault_dir / "bin.md").write_bytes(
        b"intro line\ncaf\xe9 latte\nmore text\n"
    )
    _force_backend(monkeypatch, "ripgrep")
    results = json.loads(
        vault_search("latte", file_pattern="bin.md", context_lines=0)
    )["results"]
    assert len(results) == 1
    assert results[0]["match_context"] != ""
    assert "latte" in results[0]["match_context"]


def test_default_context_lines_is_two(monkeypatch, vault_dir):
    """Callers that omit context_lines get a two-line window on each side."""
    (vault_dir / "sample.md").write_text(SAMPLE)
    _force_backend(monkeypatch, "python")
    results = json.loads(
        vault_search("TARGET", file_pattern="sample.md")
    )["results"]
    assert results[0]["match_context"] == (
        "alpha one\nbeta two\nTARGET middle\ngamma four\ndelta five"
    )


# --- context re-read hardening (symlink safety + memory bound) -----------------
#
# The ripgrep backend re-reads each matched file to assemble context. The path
# comes back from a separate ripgrep process and the file is opened in a second
# syscall, so the re-read must not (a) follow a symlink out of the vault, nor
# (b) read an unbounded amount into memory. ripgrep itself never follows
# symlinks, so these tests feed _search_ripgrep a crafted match event to stand
# in for a path that became unsafe between the scan and the re-read.


def test_ripgrep_reread_does_not_follow_symlink_to_outside_file(
    monkeypatch, vault_dir, tmp_path
):
    """A matched path that is itself a symlink pointing out of the vault (e.g. a
    note swapped for a symlink between rg's scan and the re-read) must not leak
    the target's contents; the backend degrades to rg's matched line."""
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET 0\nSECRET 1\nSECRET 2\n")
    evil = vault_dir / "evil.md"
    evil.symlink_to(secret)

    monkeypatch.setattr(
        search_mod.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(stdout=_rg_match_json(evil, 2, "decoy match\n")),
    )

    results = search_mod._search_ripgrep(
        "x", vault_dir, file_pattern="*.md", max_results=10, context_lines=2
    )
    assert len(results) == 1
    ctx = results[0]["match_context"]
    assert "SECRET" not in ctx, f"symlink re-read leaked outside content: {ctx}"
    assert ctx == "decoy match"


def test_ripgrep_reread_rejects_match_under_symlinked_parent(
    monkeypatch, vault_dir, tmp_path
):
    """A match reached through a symlinked parent directory must be refused. The
    re-read walks each component with O_NOFOLLOW relative to its parent's dir fd,
    so a symlinked intermediate directory fails the open; the no-dir_fd fallback
    catches the same case with its resolved-path containment check."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.md").write_text("SECRET a\nSECRET b\nSECRET c\n")
    link_dir = vault_dir / "linkdir"
    link_dir.symlink_to(outside, target_is_directory=True)
    target = link_dir / "secret.md"  # under vault lexically, outside once resolved

    monkeypatch.setattr(
        search_mod.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            stdout=_rg_match_json(target, 2, "decoy match\n")
        ),
    )

    results = search_mod._search_ripgrep(
        "x", vault_dir, file_pattern="*.md", max_results=10, context_lines=2
    )
    assert len(results) == 1
    ctx = results[0]["match_context"]
    assert "SECRET" not in ctx, f"symlinked-parent re-read leaked: {ctx}"
    assert ctx == "decoy match"


def test_ripgrep_oversized_file_degrades_to_matched_line(monkeypatch, vault_dir):
    """A matched file larger than the re-read cap is not read in full (which
    bounds memory); the backend degrades to rg's matched line with no context.

    Faked subprocess.run so the memory-bound case is covered even with no rg on
    PATH; the line below the TARGET would appear as context if the file were
    read, so its absence proves the cap forced the degrade."""
    monkeypatch.setattr(search_mod.config, "MAX_SEARCH_REREAD_BYTES", 64)
    big = vault_dir / "big.md"
    big.write_text("pad line\n" * 50 + "TARGET line\n" + "pad line\n" * 50)

    monkeypatch.setattr(
        search_mod.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(stdout=_rg_match_json(big, 51, "TARGET line\n")),
    )

    results = search_mod._search_ripgrep(
        "TARGET", vault_dir, file_pattern="big.md", max_results=10, context_lines=3
    )
    assert len(results) == 1
    assert results[0]["match_context"] == "TARGET line"


@requires_rg
def test_ripgrep_oversized_file_degrades_to_matched_line_real_rg(monkeypatch, vault_dir):
    """Same memory-bound behavior, exercised through the real ripgrep binary."""
    monkeypatch.setattr(search_mod.config, "MAX_SEARCH_REREAD_BYTES", 64)
    (vault_dir / "big.md").write_text(
        "pad line\n" * 50 + "TARGET line\n" + "pad line\n" * 50
    )

    results = search_mod._search_ripgrep(
        "TARGET", vault_dir, file_pattern="big.md", max_results=10, context_lines=3
    )
    assert len(results) == 1
    assert results[0]["match_context"] == "TARGET line"


def test_reread_fallback_without_dir_fd_refuses_outside_symlink(
    monkeypatch, vault_dir, tmp_path
):
    """Where openat/dir_fd is unavailable (e.g. Windows), the re-read falls back
    to a single O_NOFOLLOW open guarded by a resolved-path containment check. It
    must still read a legitimate in-vault file and still refuse a symlink that
    resolves out of the vault. Forced on this platform by emptying
    os.supports_dir_fd so the fallback branch is actually exercised."""
    monkeypatch.setattr(search_mod.os, "supports_dir_fd", frozenset())

    (vault_dir / "ok.md").write_text("a\nb\nc\n")
    assert search_mod._read_vault_file_lines("ok.md") == ["a", "b", "c"]

    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET 0\nSECRET 1\n")
    (vault_dir / "evil.md").symlink_to(secret)
    assert search_mod._read_vault_file_lines("evil.md") is None


@requires_rg
def test_ripgrep_context_for_deeply_nested_file(monkeypatch, vault_dir):
    """The no-symlink re-read walks the path component by component; a match in a
    legitimately nested directory must still get full context (regression guard
    for the component-wise open path)."""
    nested = vault_dir / "a" / "b"
    nested.mkdir(parents=True)
    (nested / "deep.md").write_text("ctx above\nTARGET deep\nctx below\n")
    _force_backend(monkeypatch, "ripgrep")

    results = json.loads(
        vault_search("TARGET deep", file_pattern="*.md", context_lines=1)
    )["results"]
    assert len(results) == 1
    assert results[0]["path"] == "a/b/deep.md"
    assert results[0]["match_context"] == "ctx above\nTARGET deep\nctx below"


def test_ripgrep_stale_line_number_degrades_to_matched_line(monkeypatch, vault_dir):
    """If rg reports a line_number past the file's current length (a content race
    where the file shrank between rg's scan and the re-read), the backend must
    degrade to rg's matched line, not slice to an empty snippet."""
    note = vault_dir / "note.md"
    note.write_text("line one\nline two\n")  # only 2 lines on disk now

    monkeypatch.setattr(
        search_mod.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            stdout=_rg_match_json(note, 7, "the matched line\n")
        ),
    )

    results = search_mod._search_ripgrep(
        "x", vault_dir, file_pattern="*.md", max_results=10, context_lines=2
    )
    assert len(results) == 1
    assert results[0]["match_context"] == "the matched line"


# --- context re-read: parent-traversal and hardlink refusal (#39 / #53) --------
#
# openat O_NOFOLLOW refuses symlinks but not ".." (a real directory entry that
# walks up out of the vault), and it cannot distinguish an in-vault hardlink to
# an outside file from a normal note. Both re-read targets must be refused; every
# vault read path (ripgrep re-read, Python fallback, frontmatter excerpt) is
# hardened the same way and degrades fail-closed.


def test_reread_refuses_parent_directory_traversal(vault_dir, tmp_path):
    """A re-read target that escapes via '..' is refused (gated through
    resolve_vault_path), since O_NOFOLLOW does not stop a '..' component."""
    secret = tmp_path / "secret.md"  # sibling of vault_dir (tmp_path/test-vault)
    secret.write_text("SECRET x\nSECRET y\n")
    assert search_mod._read_vault_file_lines("../secret.md") is None


def test_reread_refuses_hardlink_to_outside_file(vault_dir, tmp_path):
    """An in-vault hardlink to an outside file (st_nlink > 1) is refused fail-closed
    so context cannot widen a hardlink leak. (issue #53)"""
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET 0\nSECRET 1\nSECRET 2\n")
    os.link(secret, vault_dir / "evil.md")  # st_nlink == 2, same inode
    assert search_mod._read_vault_file_lines("evil.md") is None


def test_reread_reads_normal_single_link_file(vault_dir):
    """A normal note (st_nlink == 1) is still read; the hardlink guard must not
    refuse ordinary files."""
    (vault_dir / "plain.md").write_text("a\nb\nc\n")
    assert search_mod._read_vault_file_lines("plain.md") == ["a", "b", "c"]


def test_ripgrep_reread_refuses_hardlinked_match(monkeypatch, vault_dir, tmp_path):
    """End-to-end: a hardlinked match degrades to rg's matched line, no context leak."""
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET above\nSECRET hit\nSECRET below\n")
    os.link(secret, vault_dir / "evil.md")
    monkeypatch.setattr(
        search_mod.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            stdout=_rg_match_json(vault_dir / "evil.md", 2, "decoy match\n")
        ),
    )
    results = search_mod._search_ripgrep(
        "x", vault_dir, file_pattern="*.md", max_results=10, context_lines=2
    )
    assert len(results) == 1
    ctx = results[0]["match_context"]
    assert "SECRET" not in ctx, f"hardlink re-read leaked outside content: {ctx}"
    assert ctx == "decoy match"


def test_python_backend_does_not_follow_symlink_to_outside(monkeypatch, vault_dir, tmp_path):
    """The Python fallback re-reads matched files too; it must not follow a symlink
    out of the vault."""
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET alpha\n")
    (vault_dir / "evil.md").symlink_to(secret)
    _force_backend(monkeypatch, "python")
    results = json.loads(vault_search("SECRET", file_pattern="*.md"))["results"]
    assert all(r["path"] != "evil.md" for r in results)
    assert all("SECRET" not in r["match_context"] for r in results)


def test_python_backend_refuses_hardlink_to_outside(monkeypatch, vault_dir, tmp_path):
    """The Python fallback refuses an in-vault hardlink to an outside file (#53)."""
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET beta\n")
    os.link(secret, vault_dir / "evil.md")
    _force_backend(monkeypatch, "python")
    results = json.loads(vault_search("SECRET", file_pattern="*.md"))["results"]
    assert all(r["path"] != "evil.md" for r in results)
    assert all("SECRET" not in r["match_context"] for r in results)


def test_frontmatter_excerpt_refuses_symlink_to_outside(vault_dir, tmp_path):
    """The per-result frontmatter excerpt must not follow a symlink out of the vault."""
    secret = tmp_path / "secret.md"
    secret.write_text("---\nsecret_key: leaked\n---\nbody\n")
    (vault_dir / "evil.md").symlink_to(secret)
    assert search_mod._get_frontmatter_excerpt(vault_dir / "evil.md") is None


def test_frontmatter_excerpt_refuses_hardlink_to_outside(vault_dir, tmp_path):
    """The frontmatter excerpt refuses an in-vault hardlink to an outside file (#53)."""
    secret = tmp_path / "secret.md"
    secret.write_text("---\nsecret_key: leaked\n---\nbody\n")
    os.link(secret, vault_dir / "evil.md")
    assert search_mod._get_frontmatter_excerpt(vault_dir / "evil.md") is None


def test_frontmatter_excerpt_reads_normal_file(vault_dir):
    """A normal note's frontmatter is still returned; the guards must not refuse it."""
    (vault_dir / "fm.md").write_text("---\ntitle: Hello\n---\nbody\n")
    assert search_mod._get_frontmatter_excerpt(vault_dir / "fm.md") == {"title": "Hello"}


# --- explicit resolved-target re-validation of the opened fd -------------------

_HAS_FD_PATH = hasattr(__import__("fcntl"), "F_GETPATH") or os.path.exists("/proc/self/fd")
requires_fd_path = pytest.mark.skipif(
    not _HAS_FD_PATH, reason="no fd->path facility (F_GETPATH / /proc/self/fd)"
)


@requires_fd_path
def test_fd_resolves_inside_vault_accepts_in_vault_file(vault_dir):
    """An fd for a real in-vault file re-validates as inside the vault root."""
    inside = vault_dir / "inside.md"
    inside.write_text("x")
    fd = os.open(str(inside), os.O_RDONLY)
    try:
        assert search_mod._fd_resolves_inside_vault(fd, vault_dir) is True
    finally:
        os.close(fd)


@requires_fd_path
def test_fd_resolves_inside_vault_rejects_outside_file(vault_dir, tmp_path):
    """An fd for a file outside the vault re-validates as outside (defense in depth
    behind the openat O_NOFOLLOW walk)."""
    outside = tmp_path / "outside.txt"  # tmp_path is the parent of vault_dir
    outside.write_text("y")
    fd = os.open(str(outside), os.O_RDONLY)
    try:
        assert search_mod._fd_resolves_inside_vault(fd, vault_dir) is False
    finally:
        os.close(fd)
