"""Tests for the vault analytics tools (summary / findings).

Covers the happy path over a small temp vault (missing frontmatter, broken
wikilinks, tag variants, encoding issues), wikilink classification edge cases,
the server wiring seam, and an abuse case (a path_prefix that escapes the vault
must produce a clean error, not a traceback).
"""

import json

import pytest
from pydantic import ValidationError

from obsidian_vault_mcp import server
from obsidian_vault_mcp.models import VaultAnalyticsFindingsInput
from obsidian_vault_mcp.tools.analytics import (
    vault_analytics_findings,
    vault_analytics_summary,
)


# --- summary happy path ----------------------------------------------------


def test_summary_reports_hygiene_findings(vault_dir):
    """vault_analytics_summary returns compact counts and examples."""
    (vault_dir / "missing-frontmatter.md").write_text("plain text\n", encoding="utf-8")
    (vault_dir / "broken-link.md").write_text("[[Missing Target]]\n", encoding="utf-8")
    result = json.loads(vault_analytics_summary(required_frontmatter=["status", "type"]))

    assert "error" not in result
    assert result["file_count"] >= 4
    assert result["findings"]["frontmatter_missing"] >= 2
    assert result["findings"]["broken_wikilinks"] >= 1
    # required-frontmatter validation flags the plain-text notes
    assert result["findings"]["required_frontmatter_missing"] >= 2


def test_oversized_file_is_capped_and_flagged(vault_dir, monkeypatch):
    """A file over the analyze cap is surfaced as an oversized_files finding (and the
    walk reads it only up to the cap rather than spiking memory)."""
    import obsidian_vault_mcp.tools.analytics as analytics
    monkeypatch.setattr(analytics, "_MAX_ANALYZE_BYTES", 100)
    (vault_dir / "huge.md").write_text(
        "---\nstatus: active\ntype: note\n---\n" + ("x" * 5000), encoding="utf-8"
    )

    summary = json.loads(vault_analytics_summary())
    assert summary["findings"]["oversized_files"] >= 1

    findings = json.loads(vault_analytics_findings("oversized_files"))
    assert findings["count"] >= 1
    hit = next(f for f in findings["results"] if f["path"] == "huge.md")
    assert hit["size_bytes"] > 100 and hit["limit_bytes"] == 100


def test_oversized_files_category_reachable_through_model(vault_dir):
    """oversized_files must be reachable through the MCP endpoint, not just the helper.

    Jim's catch on #59: the category was in the category_map + README but missing from the
    Literal in VaultAnalyticsFindingsInput, so the model rejected it before the logic ran.
    This drives it through the model (and the server wrapper that validates with it)."""
    assert VaultAnalyticsFindingsInput(category="oversized_files").category == "oversized_files"

    result = json.loads(server.vault_analytics_findings("oversized_files"))
    assert result.get("category") == "oversized_files"
    assert "error" not in result

    with pytest.raises(ValidationError):
        VaultAnalyticsFindingsInput(category="not_a_category")


def test_summary_flags_suspicious_tag_variants(vault_dir):
    """Tags that normalize to the same value but differ in case/whitespace are flagged."""
    (vault_dir / "a.md").write_text("---\ntags: [Project]\n---\nbody\n", encoding="utf-8")
    (vault_dir / "b.md").write_text("---\ntags: [project]\n---\nbody\n", encoding="utf-8")

    summary = json.loads(vault_analytics_summary())
    findings = json.loads(vault_analytics_findings("suspicious_tag_variants"))

    assert summary["findings"]["suspicious_tag_variants"] >= 1
    variant = next(f for f in findings["results"] if f["normalized_tag"] == "project")
    assert variant["variants"] == ["Project", "project"]
    assert variant["usage_count"] == 2


def test_summary_counts_encoding_issues(vault_dir):
    """Markdown files that are not valid UTF-8 are surfaced as encoding issues."""
    # cp1252 'ä' (0xE4) is not a valid standalone UTF-8 byte
    (vault_dir / "bad-encoding.md").write_bytes(b"caf\xe4 latte\n")

    summary = json.loads(vault_analytics_summary())
    findings = json.loads(vault_analytics_findings("encoding_issues"))

    assert summary["findings"]["encoding_issues"] >= 1
    assert any(item["path"] == "bad-encoding.md" for item in findings["results"])


# --- findings happy path ---------------------------------------------------


def test_findings_returns_broken_wikilinks(vault_dir):
    """vault_analytics_findings returns detailed category results."""
    (vault_dir / "broken-link.md").write_text("[[Missing Target]]\n", encoding="utf-8")
    result = json.loads(vault_analytics_findings("broken_wikilinks"))

    assert "error" not in result
    assert result["category"] == "broken_wikilinks"
    assert any(item["target"] == "Missing Target" for item in result["results"])


def test_findings_rejects_unknown_category_at_model(vault_dir):
    """An unsupported category is rejected by the input model."""
    with pytest.raises(ValidationError):
        VaultAnalyticsFindingsInput(category="not_a_category")


# --- wikilink classification edge cases ------------------------------------


def test_source_relative_wikilink_not_flagged(vault_dir):
    """Source-relative wikilinks should not be flagged when the target exists."""
    (vault_dir / "target-note.md").write_text("target\n", encoding="utf-8")
    source_dir = vault_dir / "reports"
    source_dir.mkdir()
    (source_dir / "report.md").write_text("[[../target-note]]\n", encoding="utf-8")

    result = json.loads(vault_analytics_summary())

    assert "error" not in result
    assert result["findings"]["broken_wikilinks"] == 0


def test_classifies_repairable_and_missing_wikilinks(vault_dir):
    """Repairable path mismatches are distinguished from truly missing targets."""
    target_dir = vault_dir / "projects"
    target_dir.mkdir()
    (target_dir / "actual-target.md").write_text("exists\n", encoding="utf-8")
    (vault_dir / "repairable-link.md").write_text("[[wrong/actual-target]]\n", encoding="utf-8")
    (vault_dir / "missing-link.md").write_text("[[Missing Target]]\n", encoding="utf-8")

    summary = json.loads(vault_analytics_summary())
    findings = json.loads(vault_analytics_findings("broken_wikilinks", max_results=10))

    assert summary["findings"]["broken_wikilinks"] == 2
    assert summary["findings"]["broken_wikilinks_repairable"] == 1
    assert summary["findings"]["broken_wikilinks_missing_target"] == 1

    repairable = next(i for i in findings["results"] if i["target"] == "wrong/actual-target")
    missing = next(i for i in findings["results"] if i["target"] == "Missing Target")
    assert repairable["status"] == "repairable_path_mismatch"
    assert repairable["resolved_candidate"] == "projects/actual-target.md"
    assert missing["status"] == "missing_target"


def test_flags_ambiguous_wikilinks(vault_dir):
    """Ambiguous basename matches are surfaced explicitly with line/column."""
    (vault_dir / "team").mkdir()
    (vault_dir / "archive").mkdir()
    (vault_dir / "team" / "roadmap.md").write_text("team\n", encoding="utf-8")
    (vault_dir / "archive" / "roadmap.md").write_text("archive\n", encoding="utf-8")
    (vault_dir / "ambiguous-link.md").write_text("[[roadmap]]\n", encoding="utf-8")

    summary = json.loads(vault_analytics_summary())
    findings = json.loads(vault_analytics_findings("broken_wikilinks"))

    assert summary["findings"]["broken_wikilinks"] == 1
    assert summary["findings"]["broken_wikilinks_ambiguous"] == 1
    finding = findings["results"][0]
    assert finding["status"] == "ambiguous_basename"
    assert finding["line"] == 1
    assert finding["column"] == 1


def test_ignores_wikilinks_in_frontmatter(vault_dir):
    """Links embedded in frontmatter metadata do not count as broken body wikilinks."""
    (vault_dir / "meta-link.md").write_text(
        "---\nrelated: \"[[Missing Target]]\"\n---\n\nBody without wikilinks.\n",
        encoding="utf-8",
    )

    summary = json.loads(vault_analytics_summary())
    assert summary["findings"]["broken_wikilinks"] == 0


def test_excluded_dirs_are_skipped(vault_dir):
    """Files under .obsidian / .trash are not analyzed."""
    trash = vault_dir / ".trash"
    trash.mkdir()
    (trash / "deleted.md").write_text("[[Missing Target]]\n", encoding="utf-8")

    summary = json.loads(vault_analytics_summary())
    assert summary["findings"]["broken_wikilinks"] == 0


# --- abuse / edge ----------------------------------------------------------


def test_path_prefix_traversal_returns_clean_error(vault_dir):
    """A path_prefix escaping the vault yields a clean error payload, not a traceback."""
    summary = json.loads(vault_analytics_summary(path_prefix=".."))
    assert "error" in summary
    assert summary["path_prefix"] == ".."

    findings = json.loads(vault_analytics_findings("broken_wikilinks", path_prefix="../escape"))
    assert "error" in findings
    assert findings["category"] == "broken_wikilinks"


def test_path_prefix_dotfile_returns_clean_error(vault_dir):
    """A dotfile/hidden-dir prefix is rejected by resolve_vault_path with a clean error."""
    summary = json.loads(vault_analytics_summary(path_prefix=".obsidian"))
    assert "error" in summary


# --- server wiring (the @mcp.tool seam, not just the helper) ---------------


def test_analytics_tools_registered_and_wired(vault_dir):
    """Tools are registered on the FastMCP server and the wrappers reach the helpers."""
    for name in ("vault_analytics_summary", "vault_analytics_findings"):
        assert server.mcp._tool_manager.get_tool(name) is not None

    (vault_dir / "broken-link.md").write_text("[[Missing Target]]\n", encoding="utf-8")

    summary = json.loads(server.vault_analytics_summary(required_frontmatter=["status"]))
    assert "error" not in summary
    assert summary["findings"]["broken_wikilinks"] >= 1

    findings = json.loads(server.vault_analytics_findings("broken_wikilinks"))
    assert findings["category"] == "broken_wikilinks"
    assert any(item["target"] == "Missing Target" for item in findings["results"])
