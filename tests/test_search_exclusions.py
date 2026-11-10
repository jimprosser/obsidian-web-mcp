"""Default search exclusions: VAULT_MCP_SEARCH_EXCLUSIONS_FILE.

Opt-in. With the variable unset nothing changes. With it set, vault_search and
vault_search_frontmatter skip the listed folders unless the caller names a path_prefix at,
inside or above one, or passes include_excluded=true.
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
    monkeypatch.setattr(config, "_search_exclusions_cache", [EXCLUDED])
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


@pytest.mark.parametrize("prefix", ["Raw/Dump", "Raw/Dump/", "Raw"])
def test_path_prefix_at_or_above_excluded_folder_searches_it(excl_vault, backend, prefix):
    result = json.loads(server.vault_search(NEEDLE, path_prefix=prefix))
    assert "Raw/Dump/hidden.md" in [r["path"] for r in result["results"]]
    assert "excluded_prefixes" not in result


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
    monkeypatch.setattr(config, "_search_exclusions_cache", None)
    monkeypatch.setattr(config, "VAULT_MCP_SEARCH_EXCLUSIONS_FILE", "")
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
    assert run(include_excluded=True) == ["Raw/Dump/hidden.md", "Raw/keep.md"]


def test_tool_descriptions_name_the_exclusions(excl_vault):
    note = config.search_exclusions_note()
    assert EXCLUDED in note and "include_excluded" in note
    for name in ("vault_search", "vault_search_frontmatter"):
        tool = server.mcp._tool_manager.get_tool(name)
        assert "include_excluded" in tool.parameters["properties"]


def test_no_note_when_unconfigured(monkeypatch):
    monkeypatch.setattr(config, "_search_exclusions_cache", [])
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
    monkeypatch.setattr(config, "_search_exclusions_cache", ["Raw [old]"])
    paths = [r["path"] for r in json.loads(server.vault_search(NEEDLE))["results"]]
    assert "Raw [old]/a.md" not in paths  # excluded literally ...
    assert "Raw o/b.md" in paths  # ... and "[old]" was not treated as a character class


# -- loading and validation (abuse inputs) -------------------------------------


def _write(tmp_path, text):
    path = tmp_path / "excl.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_normalises_and_dedupes(tmp_path):
    path = _write(tmp_path, 'exclude_prefixes:\n  - "/A/B/"\n  - "A\\\\C"\n  - "A/B"\n')
    assert config.load_search_exclusions(path) == ["A/B", "A/C"]


def test_load_empty_file_and_empty_list(tmp_path):
    assert config.load_search_exclusions(_write(tmp_path, "")) == []
    assert config.load_search_exclusions(_write(tmp_path, "exclude_prefixes: []\n")) == []


@pytest.mark.parametrize(
    "body",
    [
        "exclude_prefixes: nope\n",  # not a list
        "- just\n- a list\n",  # not a mapping
        "exclude_prefixes: [1]\n",  # not a string
        'exclude_prefixes: [""]\n',  # empty entry would exclude the whole vault
        'exclude_prefixes: ["/"]\n',  # ditto once normalised
        'exclude_prefixes: ["../outside"]\n',
        'exclude_prefixes: ["A/./B"]\n',
        "exclude_prefixes: [unclosed\n",  # malformed YAML
    ],
)
def test_load_rejects_bad_files(tmp_path, body):
    with pytest.raises(ValueError, match="VAULT_MCP_SEARCH_EXCLUSIONS_FILE"):
        config.load_search_exclusions(_write(tmp_path, body))


def test_load_rejects_missing_file(tmp_path):
    with pytest.raises(ValueError, match="no such file"):
        config.load_search_exclusions(tmp_path / "missing.yaml")


def test_validate_config_fails_closed_on_bad_file(vault_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VAULT_MCP_SEARCH_EXCLUSIONS_FILE", str(_write(tmp_path, "exclude_prefixes: 5\n")))
    with pytest.raises(ValueError, match="VAULT_MCP_SEARCH_EXCLUSIONS_FILE"):
        config.validate_config()


def test_validate_config_rejects_file_inside_vault(vault_dir, monkeypatch):
    inside = vault_dir / "excl.yaml"
    inside.write_text("exclude_prefixes: []\n")
    monkeypatch.setattr(config, "VAULT_MCP_SEARCH_EXCLUSIONS_FILE", str(inside))
    with pytest.raises(ValueError, match="inside the vault"):
        config.validate_config()


def test_validate_config_primes_cache_from_file(vault_dir, tmp_path, monkeypatch):
    path = _write(tmp_path, 'exclude_prefixes: ["X/Y"]\n')
    monkeypatch.setattr(config, "VAULT_MCP_SEARCH_EXCLUSIONS_FILE", str(path))
    monkeypatch.setattr(config, "_search_exclusions_cache", None)
    config.validate_config()
    path.write_text('exclude_prefixes: ["CHANGED"]\n')  # read once: a later edit is not seen
    assert config.search_exclusions() == ["X/Y"]


def test_unset_is_valid_and_empty(vault_dir, monkeypatch):
    monkeypatch.setattr(config, "VAULT_MCP_SEARCH_EXCLUSIONS_FILE", "")
    monkeypatch.setattr(config, "_search_exclusions_cache", None)
    config.validate_config()
    assert config.search_exclusions() == []


def test_active_exclusions_overlap_is_per_segment(monkeypatch):
    monkeypatch.setattr(config, "_search_exclusions_cache", ["A/B/C"])
    assert config.active_search_exclusions(None) == ["A/B/C"]
    assert config.active_search_exclusions("A/B/C") == []
    assert config.active_search_exclusions("A/B/C/D") == []
    assert config.active_search_exclusions("A") == []
    assert config.active_search_exclusions("A/B/CX") == ["A/B/C"]  # shared string prefix only
    assert config.active_search_exclusions("Z") == ["A/B/C"]
    assert config.active_search_exclusions(None, include_excluded=True) == []
