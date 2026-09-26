"""Extensions add file patterns to the default vault_search (#96).

An OCR extension keeps its text in sidecars ("scan.pdf.ocr.txt"). vault_search looked at
*.md only, so that text was invisible unless the caller named the pattern, and models
do not. register_search_pattern() widens the default; an explicit file_pattern is used
as given; with nothing registered the search is unchanged. Each case runs on both
backends through the registered tool, and once through a real server process where an
extension registers its pattern from register_tools.
"""

import asyncio
import json
import os
import shutil

import pytest

from obsidian_vault_mcp import content_extractors, server
from obsidian_vault_mcp.tools import search as search_mod

from ._live_server import call_tool_over_http, live_server

REQUIRE_RG = shutil.which("rg") is not None


@pytest.fixture(params=["ripgrep", "python"])
def backend(request, monkeypatch):
    if request.param == "ripgrep":
        if not REQUIRE_RG:
            if os.environ.get("VAULT_TEST_REQUIRE_TOOLS", "").strip().lower() in {"1", "true", "yes", "on"}:
                pytest.fail("ripgrep missing under VAULT_TEST_REQUIRE_TOOLS=1")
            pytest.skip("ripgrep not installed; the python backend covers this run")
    else:
        monkeypatch.setattr(search_mod.shutil, "which", lambda name: None)
    return request.param


@pytest.fixture
def vault(vault_dir):
    (vault_dir / "note.md").write_text("Zaehlerstand in der Notiz\n", encoding="utf-8")
    (vault_dir / "scan.pdf.ocr.txt").write_text("# OCR\n\nZaehlerstand im Scan\n", encoding="utf-8")
    (vault_dir / "other.txt").write_text("Zaehlerstand in einer Textdatei\n", encoding="utf-8")
    yield vault_dir
    content_extractors._search_patterns.clear()


def search(**arguments) -> set[str]:
    result = asyncio.run(server.mcp.call_tool("vault_search", arguments))
    if isinstance(result, tuple):
        result = result[0]
    payload = json.loads("".join(getattr(block, "text", "") for block in result))
    assert "error" not in payload, payload
    return {match["path"] for match in payload["results"]}


def test_without_a_registration_the_default_is_notes_only(vault, backend):
    """Control: the sidecar is really there, and the default does not see it."""
    assert search(query="Zaehlerstand", file_pattern="*.ocr.txt") == {"scan.pdf.ocr.txt"}
    assert search(query="Zaehlerstand") == {"note.md"}


def test_a_registered_pattern_joins_the_default(vault, backend):
    content_extractors.register_search_pattern("*.ocr.txt")

    assert search(query="Zaehlerstand") == {"note.md", "scan.pdf.ocr.txt"}


def test_an_explicit_pattern_is_used_as_given(vault, backend):
    content_extractors.register_search_pattern("*.ocr.txt")

    assert search(query="Zaehlerstand", file_pattern="*.md") == {"note.md"}
    assert search(query="Zaehlerstand", file_pattern="*.txt") == {"scan.pdf.ocr.txt", "other.txt"}


def test_registering_twice_or_the_default_changes_nothing(vault):
    content_extractors.register_search_pattern("*.ocr.txt")
    content_extractors.register_search_pattern("*.ocr.txt")
    content_extractors.register_search_pattern("*.md")

    assert content_extractors.default_search_patterns() == ["*.md", "*.ocr.txt"]


@pytest.mark.parametrize("bad", ["", "  ", "*.ocr .txt", "!*.md", "-x", "--pre=/bin/sh", "sub/*.txt",
                                 "sub\\*.txt", "*" * 51, None, 7])
def test_a_bad_pattern_is_refused(vault, bad):
    with pytest.raises(ValueError):
        content_extractors.register_search_pattern(bad)
    assert content_extractors.default_search_patterns() == ["*.md"]


BOOTSTRAP = '''
from obsidian_vault_mcp.content_extractors import register_search_pattern
from obsidian_vault_mcp.extensions import Extension


class SidecarSearch(Extension):
    def register_tools(self, mcp):
        register_search_pattern("*.ocr.txt")


EXTENSIONS = [SidecarSearch()]
'''


def test_an_extension_widens_the_default_search_of_a_real_server(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "note.md").write_text("Zaehlerstand in der Notiz\n", encoding="utf-8")
    (vault / "scan.pdf.ocr.txt").write_text("Zaehlerstand im Scan\n", encoding="utf-8")

    with live_server(tmp_path, vault, bootstrap=BOOTSTRAP) as (base_url, _log):
        default = call_tool_over_http(base_url, "vault_search", {"query": "Zaehlerstand"})
        notes = call_tool_over_http(base_url, "vault_search", {"query": "Zaehlerstand", "file_pattern": "*.md"})

    assert {m["path"] for m in default["results"]} == {"note.md", "scan.pdf.ocr.txt"}, default
    assert {m["path"] for m in notes["results"]} == {"note.md"}, notes
