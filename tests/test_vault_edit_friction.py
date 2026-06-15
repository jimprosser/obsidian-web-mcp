"""Tests for the vault_edit friction follow-up (P0-P2).

P0: expose the per-edit field schema (old_text/new_text) on the MCP tool,
    accept old/new aliases in addition to old_str/new_str, and share one
    alias-normalization implementation between the model and the tool.
P1: near-miss diagnostics when old_text matches zero times.
P2: dry_run reports each edit's match count against the running document the
    in-order apply produces, surfacing all mismatches instead of failing fast.
"""

import asyncio
import base64
import json
import os
import random
import time

import pytest
from pydantic import ValidationError

import obsidian_vault_mcp.tools.write as write_mod
from obsidian_vault_mcp import server
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


# --- P2: dry_run aggregates match counts, simulating the in-order apply ------

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


def test_vault_edit_dry_run_reflects_sequential_state_not_original(vault_dir):
    """Each count is measured on the running doc the apply would see, in order.

    After the first edit rewrites "beta" to "alpha", the second edit's old_text
    "alpha beta alpha" no longer exists, so a real apply fails on it. dry_run
    must report that (count 0), matching the sequential apply rather than the
    original document.
    """
    (vault_dir / "test-note.md").write_text(
        "---\nstatus: active\n---\n\nalpha beta alpha\n"
    )
    edits = [
        {"old_text": "beta", "new_text": "alpha"},          # consumes the "beta"
        {"old_text": "alpha beta alpha", "new_text": "x"},  # gone after edit 0
    ]
    dry = json.loads(vault_edit("test-note.md", edits, dry_run=True))

    matches = dry["match_counts"]
    assert matches[0]["count"] == 1
    assert matches[1]["count"] == 0  # the first edit removed it from the running doc
    assert dry["edits_applied"] == 0
    assert dry["diff"] == ""

    # Parity: the real apply must fail and write nothing, exactly as predicted.
    before = (vault_dir / "test-note.md").read_text()
    applied = json.loads(vault_edit("test-note.md", edits, dry_run=False))
    assert "error" in applied
    assert applied["changed"] is False
    assert (vault_dir / "test-note.md").read_text() == before


def test_vault_edit_dry_run_predicts_chained_duplicate_apply_failure(vault_dir):
    """A chained edit set that previews unique-against-original but fails on apply.

    Counted against the original both old_texts are unique, so the buggy preview
    reported success. Applied in order, the first edit's new_text introduces a
    second occurrence of the second edit's old_text, so apply finds two matches
    and fails. dry_run must predict the failure instead of previewing success.
    """
    (vault_dir / "test-note.md").write_text("one two\n")
    edits = [
        {"old_text": "one", "new_text": "one two"},  # introduces a 2nd "two"
        {"old_text": "two", "new_text": "TWO"},       # now matches twice on apply
    ]

    dry = json.loads(vault_edit("test-note.md", edits, dry_run=True))
    assert dry["match_counts"][0]["count"] == 1
    assert dry["match_counts"][1]["count"] == 2  # the duplicate edit 0 creates
    assert dry["edits_applied"] == 0
    assert dry["diff"] == ""

    # Parity: the real apply must fail and write nothing.
    before = (vault_dir / "test-note.md").read_text()
    applied = json.loads(vault_edit("test-note.md", edits, dry_run=False))
    assert "error" in applied
    assert applied["changed"] is False
    assert (vault_dir / "test-note.md").read_text() == before


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


# --- near-miss DoS guard -----------------------------------------------------


def test_near_miss_skipped_for_oversized_old_text():
    """An old_text past the cap is skipped outright: not a plausible single-line
    near-miss, even when a line would otherwise match it perfectly."""
    big = "x" * (write_mod._NEAR_MISS_MAX_OLD_TEXT + 1)
    content = big + "\nanother line\n"
    assert write_mod._find_near_miss(content, big) is None


def test_near_miss_large_old_text_does_not_pin_cpu():
    """Regression: a large, high-entropy, zero-match old_text must not run the
    per-line SequenceMatcher. Before the size cap this pinned the CPU for minutes
    (an authenticated DoS, since old_text is bounded only by the per-edit limit);
    the cap short-circuits it, so this returns None effectively instantly."""
    content = "\n".join("line %d has some ordinary content" % i for i in range(1000))
    huge = base64.b64encode(os.urandom(800_000)).decode()  # ~1.06 MB, high entropy
    start = time.monotonic()
    result = write_mod._find_near_miss(content, huge)
    elapsed = time.monotonic() - start
    assert result is None
    assert elapsed < 5.0, f"near-miss took {elapsed:.1f}s; size cap not applied"


def test_near_miss_capped_old_text_over_huge_file_is_bounded():
    """Even an old_text at the size cap must not pin the CPU against a large
    many-line file: per-line SequenceMatcher cost grows with old_text * lines, so
    the cumulative work budget stops the scan. (~15 s unbounded for this input.)"""
    old = "x" * write_mod._NEAR_MISS_MAX_OLD_TEXT  # at the cap, so not skipped
    content = "\n".join("line %d ordinary content here" % i for i in range(25000))
    start = time.monotonic()
    write_mod._find_near_miss(content, old)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"near-miss took {elapsed:.1f}s; work budget not applied"


def test_near_miss_low_alphabet_lines_stay_bounded():
    """difflib's worst case is a low-alphabet, autojunk-disabled (sub-200-char)
    line: maximum matching blocks per line, where len(old_text)*len(line) most
    underestimates the real cost. The cumulative work budget must bound this too,
    not just benign high-entropy content."""
    rng = random.Random(99)
    old = "".join(rng.choice("ab") for _ in range(write_mod._NEAR_MISS_MAX_OLD_TEXT))
    content = "\n".join(
        "".join(rng.choice("ab") for _ in range(199)) for _ in range(3000)
    )
    start = time.monotonic()
    write_mod._find_near_miss(content, old)
    elapsed = time.monotonic() - start
    assert elapsed < 5.0, f"low-alphabet near-miss took {elapsed:.1f}s; budget too loose"


# --- wrapper-level coverage through the registered server.vault_edit ----------
# The MCP-facing entry point has a different failure contract from the direct
# call: malformed edits (empty old_text, alias conflicts) are rejected by the
# input model BEFORE the write tool runs, while a well-formed edit that simply
# does not match returns a JSON error and writes nothing.

def test_server_vault_edit_accepts_old_new_aliases(vault_dir):
    """The registered tool normalizes old/new aliases and applies the edit."""
    result = json.loads(server.vault_edit(
        "test-note.md",
        [{"old": "some content", "new": "more focused content"}],
    ))
    assert "error" not in result
    assert result["changed"] is True
    assert "more focused content" in (vault_dir / "test-note.md").read_text()


def test_server_vault_edit_rejects_conflicting_aliases(vault_dir):
    """A canonical field plus its alias is rejected by the input model; file untouched."""
    before = (vault_dir / "test-note.md").read_text()
    with pytest.raises(ValidationError):
        server.vault_edit(
            "test-note.md",
            [{"old_text": "some content", "old": "some content", "new_text": "x"}],
        )
    assert (vault_dir / "test-note.md").read_text() == before


def test_server_vault_edit_rejects_empty_old_text(vault_dir):
    """Empty old_text is rejected by the model (min_length=1) before any write.

    An empty old_text would otherwise count as a phantom match at every position;
    the registered tool's schema refuses it outright so the data-loss path is
    never reached through the MCP entry point.
    """
    before = (vault_dir / "test-note.md").read_text()
    with pytest.raises(ValidationError):
        server.vault_edit("test-note.md", [{"old_text": "", "new_text": "x"}])
    assert (vault_dir / "test-note.md").read_text() == before


def test_server_vault_edit_leaves_file_unchanged_on_non_matching_edit(vault_dir):
    """A well-formed edit that matches zero times returns an error and writes nothing."""
    before = (vault_dir / "test-note.md").read_text()
    result = json.loads(server.vault_edit(
        "test-note.md",
        [{"old_text": "does-not-exist", "new_text": "x"}],
    ))
    assert "error" in result
    assert result["changed"] is False
    assert (vault_dir / "test-note.md").read_text() == before


def test_server_vault_edit_is_atomic_when_a_later_edit_fails(vault_dir):
    """If any edit in the set fails, an earlier matching edit is not partially written."""
    before = (vault_dir / "test-note.md").read_text()
    result = json.loads(server.vault_edit(
        "test-note.md",
        [
            {"old_text": "some content", "new_text": "REPLACED"},  # matches once
            {"old_text": "does-not-exist", "new_text": "x"},        # fails
        ],
    ))
    assert "error" in result
    assert result["changed"] is False
    after = (vault_dir / "test-note.md").read_text()
    assert after == before
    assert "REPLACED" not in after
