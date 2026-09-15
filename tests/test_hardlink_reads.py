"""Read boundaries must reject real hardlinks, including bytes already read by rg."""

import json
import os
import shutil
import subprocess

import pytest

from obsidian_vault_mcp import server, vault
from obsidian_vault_mcp.tools import search

requires_rg = pytest.mark.skipif(shutil.which("rg") is None, reason="ripgrep not installed")
SECRET = "SECRET hunter2 token"
CONTENT = f"---\nsecret: {SECRET}\n---\nbefore\n{SECRET}\nafter\n"


@pytest.fixture(params=["outside_hardlink", "inside_hardlink", "outside_symlink"])
def refused_file(request, vault_dir, tmp_path):
    source = (vault_dir if request.param == "inside_hardlink" else tmp_path) / "secret.txt"
    source.write_text(CONTENT, encoding="utf-8")
    target = vault_dir / "evil.md"
    if request.param == "outside_symlink":
        target.symlink_to(source)
    else:
        os.link(source, target)
        assert target.stat().st_nlink == 2
    return target


@pytest.fixture(params=[pytest.param("rg", marks=requires_rg), "python"])
def backend(request, monkeypatch):
    if request.param == "python":
        monkeypatch.setattr(search.shutil, "which", lambda _: None)
    return request.param


def test_registered_search_drops_refused_file(vault_dir, refused_file, backend):
    if backend == "rg" and not refused_file.is_symlink():
        # Establish that REAL rg actually emits the secret; no fake subprocess output.
        raw = subprocess.run(
            ["rg", "--json", "-e", SECRET, str(refused_file)],
            capture_output=True, text=True, check=True,
        )
        assert SECRET in raw.stdout
    result = json.loads(server.vault_search(SECRET))
    assert result["results"] == []
    assert result["total_matches"] == 0
    assert SECRET not in json.dumps(result)


def test_registered_read_refuses_file(vault_dir, refused_file):
    result = json.loads(server.vault_read(refused_file.name))
    assert "error" in result
    assert "content" not in result
    assert SECRET not in json.dumps(result)
    with pytest.raises(ValueError):
        vault.read_file(refused_file.name)


def test_excerpt_refuses_file(vault_dir, refused_file):
    assert search._get_frontmatter_excerpt(refused_file) is None


def test_single_link_file_still_reads_and_matches(vault_dir, backend):
    target = vault_dir / "ordinary.md"
    target.write_text(CONTENT, encoding="utf-8")
    assert target.stat().st_nlink == 1
    read = json.loads(server.vault_read(target.name))
    assert read["content"] == CONTENT
    assert read["frontmatter"] == {"secret": SECRET}
    result = json.loads(server.vault_search(SECRET))
    assert result["total_matches"] == 2
    assert all(match["path"] == target.name for match in result["results"])
    assert all(SECRET in match["match_context"] for match in result["results"])
    assert all(match["frontmatter_excerpt"] == {"secret": SECRET} for match in result["results"])


def test_registered_search_excerpt_rechecks_file(vault_dir, tmp_path, backend, monkeypatch):
    """The excerpt read must independently refuse a hardlink introduced after search."""
    target = vault_dir / "ordinary.md"
    target.write_text("public match\n", encoding="utf-8")
    source = tmp_path / "secret.txt"
    source.write_text(CONTENT, encoding="utf-8")
    backend_name = "_search_ripgrep" if backend == "rg" else "_search_python"
    real_search = getattr(search, backend_name)

    def search_then_replace(*args):
        matches = real_search(*args)
        assert len(matches) == 1
        target.unlink()
        os.link(source, target)
        return matches

    monkeypatch.setattr(search, backend_name, search_then_replace)
    result = json.loads(server.vault_search("public match"))
    assert result["results"][0]["frontmatter_excerpt"] is None
    assert SECRET not in json.dumps(result)
