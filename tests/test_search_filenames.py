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


def test_path_prefix_scopes_to_matching_subtree(named_notes):
    """A filename match inside the path_prefix subtree is returned."""
    result = json.loads(vault_search("nyc", path_prefix="Trips"))
    paths = [r["path"] for r in result["results"]]
    assert "Trips/2026/NYC.md" in paths


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


def test_symlinked_file_is_never_matched_by_name(named_notes, tmp_path):
    """A symlink inside the vault is skipped: matching it by name would read
    (and disclose the existence of) a file outside the vault through the link."""
    outside = tmp_path / "outside-secret-nyc.md"
    outside.write_text("---\nsecret: yes\n---\n\nOutside the vault.\n")
    (named_notes / "evil-nyc-link.md").symlink_to(outside)
    result = json.loads(vault_search("nyc"))
    paths = [r["path"] for r in result["results"]]
    assert "evil-nyc-link.md" not in paths


def test_dot_directory_note_is_never_matched_by_name(named_notes):
    """Notes under any dot-prefixed path component are skipped, matching the
    rule resolve_vault_path enforces on reads."""
    hidden_dir = named_notes / ".space"
    hidden_dir.mkdir()
    (hidden_dir / "hidden-nyc.md").write_text("Hidden note.\n")
    (named_notes / ".nyc-dotfile.md").write_text("Dotfile note.\n")
    result = json.loads(vault_search("nyc"))
    paths = [r["path"] for r in result["results"]]
    assert ".space/hidden-nyc.md" not in paths
    assert ".nyc-dotfile.md" not in paths


def test_filename_matches_carry_no_frontmatter_excerpt(named_notes):
    """Name-only hits do not read the file at all: the path locates the note,
    and reading frontmatter would be an unbounded cost and a disclosure vector."""
    (named_notes / "tagged.md").write_text("---\nstatus: active\n---\n\nBody.\n")
    result = json.loads(vault_search("tagged"))
    match = next(r for r in result["results"] if r["path"] == "tagged.md")
    assert match["match_type"] == "filename"
    assert "frontmatter_excerpt" not in match


def test_content_matches_keep_frontmatter_excerpt(named_notes):
    """Content hits still carry the frontmatter excerpt they had before."""
    (named_notes / "tagged.md").write_text("---\nstatus: active\n---\n\nUnique zebra body.\n")
    result = json.loads(vault_search("unique zebra"))
    match = next(r for r in result["results"] if r["path"] == "tagged.md")
    assert match["match_type"] == "content"
    assert match["frontmatter_excerpt"] == {"status": "active"}


def test_content_hit_survives_when_name_hits_exceed_cap(named_notes):
    """Filename hits get at most half of max_results, so a body match that
    main returned is never starved out by a query that is also a folder or
    name token; leftover budget is backfilled with more name hits."""
    meetings = named_notes / "Meetings"
    meetings.mkdir()
    for i in range(10):
        (meetings / f"meeting-{i:02d}.md").write_text("Notes.\n")
    (named_notes / "agenda.md").write_text("Weekly meeting agenda.\n")

    result = json.loads(vault_search("meeting", max_results=6))

    assert len(result["results"]) == 6
    assert result["truncated"] is True
    content_hits = [r for r in result["results"] if r["match_type"] == "content"]
    assert [r["path"] for r in content_hits] == ["agenda.md"]
    # the slot content did not need is backfilled with name hits
    assert len([r for r in result["results"] if r["match_type"] == "filename"]) == 5


def test_file_matching_by_name_and_content_appears_once(named_notes):
    """A file that matches both by name and by content is returned once, as
    the content match (which carries the line and context)."""
    fruit = named_notes / "Fruit"
    fruit.mkdir()
    (fruit / "banana.md").write_text("A banana bread recipe.\n")

    result = json.loads(vault_search("banana"))

    hits = [r for r in result["results"] if r["path"] == "Fruit/banana.md"]
    assert len(hits) == 1
    assert hits[0]["match_type"] == "content"


def test_registered_tool_returns_filename_matches(named_notes):
    """The registered server tool (input validation + audit wrapper) surfaces
    filename matches, not just the helper."""
    from obsidian_vault_mcp import server

    result = json.loads(server.vault_search("nyc"))
    paths = [r["path"] for r in result["results"]]
    assert "Trips/2026/NYC.md" in paths


def test_python_fallback_finds_filenames(named_notes, monkeypatch):
    """Filename matching works identically when ripgrep is unavailable."""
    import obsidian_vault_mcp.tools.search as search_mod

    monkeypatch.setattr(search_mod.shutil, "which", lambda _: None)
    result = json.loads(vault_search("nyc"))
    paths = [r["path"] for r in result["results"]]
    assert "Trips/2026/NYC.md" in paths
