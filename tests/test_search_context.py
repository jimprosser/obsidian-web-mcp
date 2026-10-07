"""vault_search returns the same context lines on both backends (#39).

The ripgrep backend passed --context to rg and dropped every "context" event, so
match_context held only the matching line, while the Python fallback returned the lines
around it. Same arguments, different answers depending on whether rg is installed. Every
case runs through the registered tool on both backends; the last one compares the whole
payload of both.
"""

import asyncio
import json
import os
import shutil

import pytest

from obsidian_vault_mcp import server
from obsidian_vault_mcp.tools import search as search_mod

HAVE_RG = shutil.which("rg") is not None
REQUIRE = os.environ.get("VAULT_TEST_REQUIRE_TOOLS", "").strip().lower() in {"1", "true", "yes", "on"}
BODY = "".join(f"line {n}\n" for n in range(1, 11)).replace("line 5\n", "line 5 Zaehlerstand\n")


@pytest.fixture(params=["ripgrep", "python"])
def backend(request, monkeypatch):
    if request.param == "ripgrep":
        if not HAVE_RG:
            if REQUIRE:
                pytest.fail("ripgrep missing under VAULT_TEST_REQUIRE_TOOLS=1")
            pytest.skip("ripgrep not installed; the python backend covers this run")
    else:
        monkeypatch.setattr(search_mod.shutil, "which", lambda name: None)
    return request.param


def search(**arguments) -> list[dict]:
    result = asyncio.run(server.mcp.call_tool("vault_search", arguments))
    if isinstance(result, tuple):
        result = result[0]
    payload = json.loads("".join(getattr(block, "text", "") for block in result))
    assert "error" not in payload, payload
    return [hit for hit in payload["results"] if hit.get("match_type") == "content"]


def test_the_window_around_a_match(vault_dir, backend):
    (vault_dir / "n.md").write_text(BODY, encoding="utf-8")

    (hit,) = search(query="Zaehlerstand", context_lines=2)

    assert hit["line_number"] == 5
    assert hit["match_context"] == "line 3\nline 4\nline 5 Zaehlerstand\nline 6\nline 7"


@pytest.mark.parametrize("body,expected", [
    ("Zaehlerstand first\nb\nc\nd\n", "Zaehlerstand first\nb\nc"),
    ("a\nb\nc\nZaehlerstand last\n", "b\nc\nZaehlerstand last"),
    ("a\nb\nc\nZaehlerstand last, no newline", "b\nc\nZaehlerstand last, no newline"),
])
def test_missing_neighbours_at_the_edges_are_left_out(vault_dir, backend, body, expected):
    (vault_dir / "n.md").write_text(body, encoding="utf-8")

    (hit,) = search(query="Zaehlerstand", context_lines=2)

    assert hit["match_context"] == expected


def test_zero_context_is_the_matching_line(vault_dir, backend):
    (vault_dir / "n.md").write_text(BODY, encoding="utf-8")

    (hit,) = search(query="Zaehlerstand", context_lines=0)

    assert hit["match_context"] == "line 5 Zaehlerstand"


def test_close_matches_each_get_their_own_window(vault_dir, backend):
    (vault_dir / "n.md").write_text("a\nZaehlerstand one\nb\nZaehlerstand two\nc\n", encoding="utf-8")

    hits = search(query="Zaehlerstand", context_lines=1)

    assert [(h["line_number"], h["match_context"]) for h in hits] == [
        (2, "a\nZaehlerstand one\nb"), (4, "b\nZaehlerstand two\nc")]


def test_crlf_line_endings_leave_no_carriage_return(vault_dir, backend):
    (vault_dir / "n.md").write_bytes(b"a\r\nb\r\nZaehlerstand\r\nc\r\nd\r\n")

    (hit,) = search(query="Zaehlerstand", context_lines=1)

    assert hit["match_context"] == "b\nZaehlerstand\nc"


def test_a_note_with_binary_content_does_not_break_the_search(vault_dir, backend):
    (vault_dir / "odd.md").write_bytes(b"Zaehlerstand\x00\x01\x02\n")
    (vault_dir / "n.md").write_text(BODY, encoding="utf-8")

    hits = search(query="Zaehlerstand", context_lines=1)

    assert ("n.md", 5) in [(h["path"], h["line_number"]) for h in hits]


def test_max_results_still_caps_content_hits(vault_dir, backend):
    for n in range(5):
        (vault_dir / f"n{n}.md").write_text(BODY, encoding="utf-8")

    hits = search(query="Zaehlerstand", context_lines=2, max_results=3)

    assert len(hits) <= 3
    assert all(h["match_context"].count("\n") == 4 for h in hits)


def test_both_backends_return_the_same_payload(vault_dir, monkeypatch):
    """Parity over one vault: every field of every hit, for several context sizes."""
    if not HAVE_RG:
        if REQUIRE:
            pytest.fail("ripgrep missing under VAULT_TEST_REQUIRE_TOOLS=1")
        pytest.skip("ripgrep not installed")
    (vault_dir / "a.md").write_text(BODY, encoding="utf-8")
    (vault_dir / "b.md").write_bytes(b"x\r\nZaehlerstand b\r\ny\r\n")
    (vault_dir / "c.md").write_text("Zaehlerstand c1\nm\nn\no\nZaehlerstand c2\n", encoding="utf-8")

    def payload(context_lines):
        hits = search(query="Zaehlerstand", context_lines=context_lines)
        return sorted((h["path"], h["line_number"], h["match_context"]) for h in hits)

    for context_lines in (0, 1, 3):
        with_rg = payload(context_lines)
        with monkeypatch.context() as m:
            m.setattr(search_mod.shutil, "which", lambda name: None)
            without_rg = payload(context_lines)
        assert with_rg and with_rg == without_rg, context_lines
