"""Tests for vault_search context_lines behavior across both search backends.

Regression coverage for the bug where the ripgrep backend passed --context to
rg but discarded the resulting context events, so context_lines was a no-op on
the ripgrep path while the Python fallback honored it. The two backends must
return identical match_context for the same query.
"""

import json
import shutil

import pytest

import obsidian_vault_mcp.tools.search as search_mod
from obsidian_vault_mcp.tools.search import vault_search

RG_AVAILABLE = shutil.which("rg") is not None
requires_rg = pytest.mark.skipif(not RG_AVAILABLE, reason="ripgrep not installed")

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

    from pathlib import Path

    real_read_bytes = Path.read_bytes

    def failing_read_bytes(self, *args, **kwargs):
        if self.name == "sample.md":
            raise OSError("simulated read failure")
        return real_read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(
        "obsidian_vault_mcp.tools.search.Path.read_bytes", failing_read_bytes
    )

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
