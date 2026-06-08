"""Tests for the vault_edit friction follow-up (P0-P2).

P0: expose the per-edit field schema (old_text/new_text) on the MCP tool,
    accept old/new aliases in addition to old_str/new_str, and share one
    alias-normalization implementation between the model and the tool.
P1: near-miss diagnostics when old_text matches zero times.
P2: dry_run reports each edit's match count against the original document
    instead of failing fast at the first non-unique match.
"""

import asyncio
import json

import pytest

from obsidian_vault_mcp.models import VaultEditOperationInput
from obsidian_vault_mcp.server import mcp
from obsidian_vault_mcp.tools.write import vault_edit


def _vault_edit_input_schema() -> dict:
    async def _collect() -> dict:
        for tool in await mcp.list_tools():
            if tool.name == "vault_edit":
                return tool.inputSchema
        raise AssertionError("vault_edit tool not registered")

    return asyncio.run(_collect())


# --- P0: schema exposure -----------------------------------------------------

def test_vault_edit_schema_exposes_edit_operation_fields():
    """The MCP input schema advertises old_text/new_text on each edit object."""
    schema = _vault_edit_input_schema()
    blob = json.dumps(schema)

    assert "old_text" in blob, "edit field schema must expose old_text"
    assert "new_text" in blob, "edit field schema must expose new_text"

    # The edits array items must no longer be an opaque object.
    items = schema["properties"]["edits"]["items"]
    assert items != {"additionalProperties": True, "type": "object"}


# --- P0: alias expansion at the model level ----------------------------------

def test_edit_operation_accepts_old_new_aliases():
    op = VaultEditOperationInput(old="foo", new="bar")
    assert op.old_text == "foo"
    assert op.new_text == "bar"


def test_edit_operation_rejects_conflicting_old_aliases():
    with pytest.raises(ValueError):
        VaultEditOperationInput(old="foo", old_str="foo", new="bar")


# --- P0: alias expansion through the tool ------------------------------------

def test_vault_edit_accepts_old_new_aliases(vault_dir):
    result = json.loads(vault_edit(
        "test-note.md",
        [{"old": "some content", "new": "more focused content"}],
    ))

    assert "error" not in result
    assert result["changed"] is True
    assert result["edits_applied"] == 1
    assert "more focused content" in (vault_dir / "test-note.md").read_text()


def test_vault_edit_rejects_mixed_old_and_old_alias(vault_dir):
    before = (vault_dir / "test-note.md").read_text()

    result = json.loads(vault_edit(
        "test-note.md",
        [{"old": "some content", "old_str": "some content", "new": "x"}],
    ))

    assert "error" in result
    assert result["changed"] is False
    assert (vault_dir / "test-note.md").read_text() == before


# --- P1: near-miss diagnostics ----------------------------------------------

def test_vault_edit_zero_match_reports_near_miss(vault_dir):
    """A single-character typo surfaces the closest line with a high similarity."""
    result = json.loads(vault_edit(
        "test-note.md",
        # actual text contains "some content"; introduce a typo
        [{"old_text": "some kontent", "new_text": "x"}],
    ))

    assert "error" in result
    assert result["changed"] is False
    nm = result.get("near_miss")
    assert nm, "zero-match error should carry a near_miss hint"
    assert "some content" in nm["line"]
    # A one-character typo must score as clearly similar, otherwise the hint is
    # indistinguishable from unrelated input and the feature is pointless.
    assert nm["similarity"] > 0.6


def test_vault_edit_zero_match_unrelated_input_has_no_false_near_miss(vault_dir):
    """Input unrelated to any line does not fabricate a near_miss hint at all."""
    result = json.loads(vault_edit(
        "test-note.md",
        [{"old_text": "zzzzz totally unrelated payload qqqqq", "new_text": "x"}],
    ))

    assert "error" in result
    assert result["changed"] is False
    # Below the similarity floor: no misleading hint is emitted.
    assert result.get("near_miss") is None


def test_vault_edit_multiline_zero_match_is_coherent(vault_dir):
    """A multi-line old_text that does not match yields a coherent error, no crash."""
    (vault_dir / "test-note.md").write_text(
        "---\nstatus: active\n---\n\nfirst line here\nsecond line here\n"
    )
    result = json.loads(vault_edit(
        "test-note.md",
        [{"old_text": "first line here\nsecnd line here", "new_text": "x"}],
    ))

    assert "error" in result
    assert result["changed"] is False
    # near_miss is optional for multi-line input, but if present it must be a
    # real line from the file with a bounded similarity.
    nm = result.get("near_miss")
    if nm:
        assert 0.0 <= nm["similarity"] <= 1.0
        assert nm["line"] in (vault_dir / "test-note.md").read_text()


def test_vault_edit_missing_old_text_reports_explicit_error(vault_dir):
    """An edit with no old_text fails with a clear message, not a phantom count."""
    before = (vault_dir / "test-note.md").read_text()
    result = json.loads(vault_edit(
        "test-note.md",
        [{"new_text": "x"}],
    ))

    assert "error" in result
    assert "match" not in result["error"] or "old_text" in result["error"]
    assert "found" not in result["error"], "must not report a fabricated match count"
    assert result["changed"] is False
    assert (vault_dir / "test-note.md").read_text() == before


# --- P2: dry_run aggregates match counts against the original ----------------

def test_vault_edit_dry_run_aggregates_all_match_counts(vault_dir):
    """dry_run reports every edit's match count instead of failing at the first."""
    result = json.loads(vault_edit(
        "test-note.md",
        [
            {"old_text": "some content", "new_text": "a"},          # 1 match
            {"old_text": "does-not-exist", "new_text": "b"},        # 0 matches
            {"old_text": "t", "new_text": "c"},                     # many matches
        ],
        dry_run=True,
    ))

    matches = result.get("match_counts")
    assert matches is not None, "dry_run should report per-edit match counts"
    assert matches[0]["count"] == 1
    assert matches[1]["count"] == 0
    assert matches[2]["count"] > 1
    # the zero-count edit carries a near_miss in the dry_run path too
    assert matches[1].get("near_miss") is not None
    # a non-unique set is not applicable: no diff preview, nothing counted applied
    assert result["diff"] == ""
    assert result["edits_applied"] == 0
    # nothing written
    assert result["changed"] is False


def test_vault_edit_dry_run_all_unique_previews_diff_without_writing(vault_dir):
    """When every edit matches once, dry_run returns the diff and applies nothing."""
    before = (vault_dir / "test-note.md").read_text()
    result = json.loads(vault_edit(
        "test-note.md",
        [{"old_text": "some content", "new_text": "more focused content"}],
        dry_run=True,
    ))

    assert result["changed"] is False
    assert result["edits_applied"] == 1
    assert result["match_counts"] == [{"index": 0, "count": 1}]
    assert "more focused content" in result["diff"]
    assert (vault_dir / "test-note.md").read_text() == before


def test_vault_edit_dry_run_accepts_old_new_aliases(vault_dir):
    """old/new aliases are normalized before the dry_run fork."""
    result = json.loads(vault_edit(
        "test-note.md",
        [{"old": "some content", "new": "x"}],
        dry_run=True,
    ))

    assert result["match_counts"] == [{"index": 0, "count": 1}]
    assert result["edits_applied"] == 1
    assert "error" not in result


def test_vault_edit_dry_run_counts_against_original_not_sequential(vault_dir):
    """Each count is measured on the original document, independent of order."""
    # Two edits whose old_text both exist in the original; first edit's
    # replacement must not change the second edit's reported count.
    (vault_dir / "test-note.md").write_text(
        "---\nstatus: active\n---\n\nalpha beta alpha\n"
    )
    result = json.loads(vault_edit(
        "test-note.md",
        [
            {"old_text": "beta", "new_text": "alpha"},  # would add an alpha if applied
            {"old_text": "alpha beta alpha", "new_text": "x"},  # 1 in original
        ],
        dry_run=True,
    ))

    matches = result["match_counts"]
    assert matches[0]["count"] == 1
    assert matches[1]["count"] == 1


def test_vault_edit_apply_still_fails_fast_on_non_unique(vault_dir):
    """Real application (dry_run=False) keeps the fail-fast safety net."""
    before = (vault_dir / "test-note.md").read_text()
    result = json.loads(vault_edit(
        "test-note.md",
        [{"old_text": "t", "new_text": "X"}],  # many matches
        dry_run=False,
    ))

    assert "error" in result
    assert result["changed"] is False
    assert (vault_dir / "test-note.md").read_text() == before
