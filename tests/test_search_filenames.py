"""Tests for vault_search matching note names/paths in addition to contents."""

import json

import pytest

from obsidian_vault_mcp.tools.search import vault_search


@pytest.fixture
def named_notes(vault_dir):
    """Add notes whose names matter but whose bodies avoid the query terms."""
    trips = vault_dir / "Trips" / "2026"
    trips.mkdir(parents=True)
    (trips / "NYC.md").write_text("Itinerary for the big apple trip.\n")
    (vault_dir / "banana.md").write_text("A yellow fruit I like.\n")
    (vault_dir / "other.md").write_text("I ate a banana today.\n")
    trash = vault_dir / ".trash"
    trash.mkdir()
    (trash / "NYC-old.md").write_text("Deleted trip note.\n")
    (vault_dir / "Trips" / "NYC.canvas").write_text("{}")
    return vault_dir


def test_finds_note_by_filename(named_notes):
    """A note whose name matches the query is found even if its body doesn't."""
    result = json.loads(vault_search("nyc"))
    paths = [r["path"] for r in result["results"]]
    assert "Trips/2026/NYC.md" in paths
    match = next(r for r in result["results"] if r["path"] == "Trips/2026/NYC.md")
    assert match["match_type"] == "filename"
    assert match["line_number"] is None


def test_finds_note_by_directory_component(named_notes):
    """The query matches anywhere in the vault-relative path, not just the stem."""
    result = json.loads(vault_search("2026"))
    paths = [r["path"] for r in result["results"]]
    assert "Trips/2026/NYC.md" in paths


def test_content_matches_are_tagged(named_notes):
    """Content matches carry match_type 'content' and keep their line info."""
    result = json.loads(vault_search("yellow fruit"))
    match = next(r for r in result["results"] if r["path"] == "banana.md")
    assert match["match_type"] == "content"
    assert match["line_number"] == 1


def test_filename_matches_come_first(named_notes):
    """When both kinds match, filename matches are ordered before content matches."""
    result = json.loads(vault_search("banana"))
    types = [r["match_type"] for r in result["results"]]
    assert "filename" in types
    assert "content" in types
    assert types.index("filename") < types.index("content")
    filename_match = next(r for r in result["results"] if r["match_type"] == "filename")
    assert filename_match["path"] == "banana.md"


def test_filename_matches_respect_path_prefix(named_notes):
    """path_prefix scopes filename matches like content matches."""
    result = json.loads(vault_search("nyc", path_prefix="subfolder"))
    assert result["results"] == []


def test_filename_matches_respect_file_pattern(named_notes):
    """The default *.md pattern excludes non-markdown files from filename matches."""
    result = json.loads(vault_search("nyc"))
    paths = [r["path"] for r in result["results"]]
    assert "Trips/NYC.canvas" not in paths


def test_filename_matches_skip_excluded_dirs(named_notes):
    """Files under excluded directories like .trash never match by name."""
    result = json.loads(vault_search("nyc"))
    paths = [r["path"] for r in result["results"]]
    assert ".trash/NYC-old.md" not in paths


def test_max_results_caps_combined_matches(named_notes):
    """max_results bounds filename and content matches together."""
    result = json.loads(vault_search("banana", max_results=1))
    assert len(result["results"]) == 1
    assert result["truncated"] is True


def test_filename_matches_include_frontmatter_excerpt(named_notes):
    """Filename matches get the same frontmatter enrichment as content matches."""
    (named_notes / "tagged.md").write_text("---\nstatus: active\n---\n\nBody.\n")
    result = json.loads(vault_search("tagged"))
    match = next(r for r in result["results"] if r["path"] == "tagged.md")
    assert match["frontmatter_excerpt"] == {"status": "active"}


def test_python_fallback_finds_filenames(named_notes, monkeypatch):
    """Filename matching works identically when ripgrep is unavailable."""
    import obsidian_vault_mcp.tools.search as search_mod

    monkeypatch.setattr(search_mod.shutil, "which", lambda _: None)
    result = json.loads(vault_search("nyc"))
    paths = [r["path"] for r in result["results"]]
    assert "Trips/2026/NYC.md" in paths
