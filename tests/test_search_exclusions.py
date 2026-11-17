"""Default search exclusions: VAULT_MCP_SEARCH_EXCLUDE_PREFIXES_JSON.

Opt-in. With the variable unset nothing changes. With it set, vault_search and
vault_search_frontmatter skip the listed folders unless the caller names a path_prefix at,
inside one, or passes include_excluded=true. A path_prefix above one keeps the exclusion.
"""

import json
import shutil

import pytest

from obsidian_vault_mcp import config, server
from obsidian_vault_mcp.frontmatter_index import FrontmatterIndex
from obsidian_vault_mcp.tools import search as search_mod

EXCLUDED = "Raw/Dump"
NEEDLE = "zebrafinch"


@pytest.fixture
def excl_vault(vault_dir, monkeypatch):
    """A vault with the needle in an excluded folder, a sibling and a look-alike name."""
    (vault_dir / "Raw" / "Dump").mkdir(parents=True)
    (vault_dir / "Raw" / "Dump" / "hidden.md").write_text(f"---\nkind: dump\n---\n{NEEDLE} inside\n")
    (vault_dir / "Raw" / "keep.md").write_text(f"---\nkind: keep\n---\n{NEEDLE} sibling\n")
    # Shares the string prefix "Raw/Dump" but is NOT inside the folder.
    (vault_dir / "Raw" / "Dump2.md").write_text(f"{NEEDLE} look-alike\n")
    monkeypatch.setattr(config, "SEARCH_EXCLUDE_PREFIXES", [EXCLUDED])
    return vault_dir


def _paths(raw: str) -> list[str]:
    return sorted(r["path"] for r in json.loads(raw)["results"])


@pytest.fixture(params=["python", "ripgrep"])
def backend(request, monkeypatch):
    """Run the wiring tests once on the Python walk and once through ripgrep."""
    if request.param == "ripgrep":
        if not shutil.which("rg"):
            pytest.skip("ripgrep not installed")
    else:
        monkeypatch.setattr(search_mod.shutil, "which", lambda name: None)
    return request.param


# -- the tools, end to end ----------------------------------------------------


def test_vault_wide_search_skips_excluded_folder(excl_vault, backend):
    result = json.loads(server.vault_search(NEEDLE))
    paths = [r["path"] for r in result["results"]]
    assert "Raw/Dump/hidden.md" not in paths
    assert "Raw/keep.md" in paths
    assert "Raw/Dump2.md" in paths
    assert result["excluded_prefixes"] == [EXCLUDED]


def test_filename_search_skips_excluded_folder(excl_vault, backend):
    assert "Raw/Dump/hidden.md" not in _paths(server.vault_search("hidden"))
    assert "Raw/Dump/hidden.md" in _paths(server.vault_search("hidden", include_excluded=True))


@pytest.mark.parametrize("prefix", ["Raw/Dump", "Raw/Dump/"])
def test_path_prefix_at_excluded_folder_searches_it(excl_vault, backend, prefix):
    result = json.loads(server.vault_search(NEEDLE, path_prefix=prefix))
    assert "Raw/Dump/hidden.md" in [r["path"] for r in result["results"]]
    assert "excluded_prefixes" not in result


def test_path_prefix_inside_excluded_folder_searches_it(excl_vault, backend):
    (excl_vault / "Raw" / "Dump" / "sub").mkdir()
    (excl_vault / "Raw" / "Dump" / "sub" / "deep.md").write_text(f"{NEEDLE} deep\n")
    result = json.loads(server.vault_search(NEEDLE, path_prefix="Raw/Dump/sub"))
    assert [r["path"] for r in result["results"]] == ["Raw/Dump/sub/deep.md"]
    assert "excluded_prefixes" not in result


def test_path_prefix_above_excluded_folder_keeps_exclusion(excl_vault, backend):
    result = json.loads(server.vault_search(NEEDLE, path_prefix="Raw"))
    paths = [r["path"] for r in result["results"]]
    assert "Raw/Dump/hidden.md" not in paths
    assert "Raw/keep.md" in paths
    assert result["excluded_prefixes"] == [EXCLUDED]
    # ... and include_excluded still reaches it.
    paths = [r["path"] for r in json.loads(server.vault_search(NEEDLE, path_prefix="Raw", include_excluded=True))["results"]]
    assert "Raw/Dump/hidden.md" in paths


def test_include_excluded_searches_everything(excl_vault, backend):
    result = json.loads(server.vault_search(NEEDLE, include_excluded=True))
    assert "Raw/Dump/hidden.md" in [r["path"] for r in result["results"]]
    assert "excluded_prefixes" not in result


def test_unrelated_path_prefix_keeps_exclusion_inert(excl_vault, backend):
    (excl_vault / "subfolder" / "n.md").write_text(f"{NEEDLE} elsewhere\n")
    assert _paths(server.vault_search(NEEDLE, path_prefix="subfolder")) == ["subfolder/n.md"]


def test_unset_means_no_exclusions(vault_dir, backend, monkeypatch):
    (vault_dir / "Raw" / "Dump").mkdir(parents=True)
    (vault_dir / "Raw" / "Dump" / "hidden.md").write_text(f"{NEEDLE}\n")
    monkeypatch.setattr(config, "SEARCH_EXCLUDE_PREFIXES", [])
    result = json.loads(server.vault_search(NEEDLE))
    assert "Raw/Dump/hidden.md" in [r["path"] for r in result["results"]]
    assert "excluded_prefixes" not in result


def test_frontmatter_search_wiring(excl_vault, monkeypatch):
    index = FrontmatterIndex()
    index.rebuild()
    monkeypatch.setattr(server, "frontmatter_index", index)

    def run(**kw):
        return _paths(server.vault_search_frontmatter("kind", match_type="exists", **kw))

    assert run() == ["Raw/keep.md"]
    assert run(path_prefix="Raw/Dump") == ["Raw/Dump/hidden.md"]
    assert run(path_prefix="Raw") == ["Raw/keep.md"]  # a parent keeps the exclusion
    assert run(path_prefix="Raw", include_excluded=True) == ["Raw/Dump/hidden.md", "Raw/keep.md"]
    assert run(include_excluded=True) == ["Raw/Dump/hidden.md", "Raw/keep.md"]


def test_tool_descriptions_name_the_exclusions(excl_vault):
    note = config.search_exclusions_note()
    assert EXCLUDED in note and "include_excluded" in note
    for name in ("vault_search", "vault_search_frontmatter"):
        tool = server.mcp._tool_manager.get_tool(name)
        assert "include_excluded" in tool.parameters["properties"]


def test_no_note_when_unconfigured(monkeypatch):
    monkeypatch.setattr(config, "SEARCH_EXCLUDE_PREFIXES", [])
    assert config.search_exclusions_note() == ""


# -- ripgrep specifics --------------------------------------------------------


def test_ripgrep_gets_anchored_globs_and_vault_cwd(monkeypatch, tmp_path):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"], captured["kwargs"] = cmd, kwargs
        return type("R", (), {"stdout": ""})()

    monkeypatch.setattr(search_mod.subprocess, "run", fake_run)
    search_mod._search_ripgrep("q", tmp_path, "*.md", 5, 0, exclusions=["A/B [x]"])
    assert "--glob=!A/B \\[x\\]/**" in captured["cmd"]
    assert captured["kwargs"]["cwd"] == config.VAULT_PATH


def test_ripgrep_untouched_without_exclusions(monkeypatch, tmp_path):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"], captured["kwargs"] = cmd, kwargs
        return type("R", (), {"stdout": ""})()

    monkeypatch.setattr(search_mod.subprocess, "run", fake_run)
    search_mod._search_ripgrep("q", tmp_path, "*.md", 5, 0)
    assert not [a for a in captured["cmd"] if a.endswith("/**")]
    assert "cwd" not in captured["kwargs"]


@pytest.mark.skipif(not shutil.which("rg"), reason="ripgrep not installed")
def test_ripgrep_folder_name_with_glob_characters(vault_dir, monkeypatch):
    (vault_dir / "Raw [old]").mkdir()
    (vault_dir / "Raw [old]" / "a.md").write_text(f"{NEEDLE}\n")
    (vault_dir / "Raw o").mkdir()
    (vault_dir / "Raw o" / "b.md").write_text(f"{NEEDLE}\n")
    monkeypatch.setattr(config, "SEARCH_EXCLUDE_PREFIXES", ["Raw [old]"])
    paths = [r["path"] for r in json.loads(server.vault_search(NEEDLE))["results"]]
    assert "Raw [old]/a.md" not in paths  # excluded literally ...
    assert "Raw o/b.md" in paths  # ... and "[old]" was not treated as a character class


# -- parsing and validation (abuse inputs) -------------------------------------


def test_parse_normalises_and_dedupes():
    raw = json.dumps(["/A/B/", "A" + chr(92) + "C", "A/B"])
    assert config.parse_search_exclude_prefixes(raw) == ["A/B", "A/C"]


def test_parse_unset_and_empty_list():
    assert config.parse_search_exclude_prefixes("") == []
    assert config.parse_search_exclude_prefixes("[]") == []


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        '{"a": 1}',  # not an array
        '"A/B"',  # a bare string
        "[1]",  # not a string
        '[""]',  # empty entry would exclude the whole vault
        '["/"]',  # ditto once normalised
        '["../outside"]',
        '["A/./B"]',
        '["A\u0000B"]',  # NUL
    ],
)
def test_parse_rejects_bad_values(raw):
    with pytest.raises(ValueError, match="VAULT_MCP_SEARCH_EXCLUDE_PREFIXES_JSON"):
        config.parse_search_exclude_prefixes(raw)


def test_validate_config_fails_closed_on_bad_value(vault_dir, monkeypatch):
    monkeypatch.setenv("VAULT_MCP_SEARCH_EXCLUDE_PREFIXES_JSON", '{"a": 1}')
    with pytest.raises(ValueError, match="VAULT_MCP_SEARCH_EXCLUDE_PREFIXES_JSON"):
        config.validate_config()


def test_validate_config_accepts_good_value_and_unset(vault_dir, monkeypatch):
    monkeypatch.setenv("VAULT_MCP_SEARCH_EXCLUDE_PREFIXES_JSON", '["X/Y"]')
    config.validate_config()
    monkeypatch.delenv("VAULT_MCP_SEARCH_EXCLUDE_PREFIXES_JSON")
    config.validate_config()


def test_active_exclusions_overlap_is_per_segment(monkeypatch):
    monkeypatch.setattr(config, "SEARCH_EXCLUDE_PREFIXES", ["A/B/C"])
    assert config.active_search_exclusions(None) == ["A/B/C"]
    assert config.active_search_exclusions("A/B/C") == []  # at
    assert config.active_search_exclusions("A/B/C/D") == []  # inside
    assert config.active_search_exclusions("A") == ["A/B/C"]  # above keeps it
    assert config.active_search_exclusions("A/B") == ["A/B/C"]
    assert config.active_search_exclusions("A/B/CX") == ["A/B/C"]  # shared string prefix only
    assert config.active_search_exclusions("Z") == ["A/B/C"]
    assert config.active_search_exclusions(None, include_excluded=True) == []
