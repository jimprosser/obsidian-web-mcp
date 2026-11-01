"""Tests for find_heading_section, heading-scoped vault_append, and vault_edit_section."""

import asyncio
import json

import pytest

from obsidian_vault_mcp import audit, config, context, server
from obsidian_vault_mcp.vault import find_heading_section
from obsidian_vault_mcp.tools.write import vault_append, vault_edit_section, vault_write


DOC = """# Title

Intro text.

## Track 1

Some notes about track 1.

### Sub A

Nested notes.

## Track 2

Some notes about track 2.
"""


# --- find_heading_section --------------------------------------------------

def test_section_runs_to_next_same_level_heading():
    start, end = find_heading_section(DOC, "## Track 1")
    section = DOC[start:end]
    assert "Some notes about track 1." in section
    assert "Sub A" in section  # deeper nesting stays inside the parent section
    assert "Track 2" not in section


def test_last_section_runs_to_eof():
    start, end = find_heading_section(DOC, "## Track 2")
    assert DOC[start:end] == "\nSome notes about track 2.\n"


def test_not_a_heading_line_raises():
    with pytest.raises(ValueError, match="ATX heading"):
        find_heading_section(DOC, "Track 1")


def test_missing_heading_raises():
    with pytest.raises(ValueError, match="not found"):
        find_heading_section(DOC, "## Track 99")


def test_ambiguous_heading_raises():
    dup = "## Notes\n\na\n\n## Notes\n\nb\n"
    with pytest.raises(ValueError, match="matches 2 times"):
        find_heading_section(dup, "## Notes")


# --- vault_append with heading ----------------------------------------------

def test_append_inserts_before_next_heading(vault_dir):
    vault_write("doc.md", DOC)
    result = json.loads(vault_append("doc.md", "New line for track 1.", heading="## Track 1"))
    assert result["changed"] is True

    content = (vault_dir / "doc.md").read_text()
    track1 = content.split("## Track 1")[1].split("## Track 2")[0]
    assert "New line for track 1." in track1
    assert content.index("New line for track 1.") < content.index("## Track 2")


def test_append_with_heading_requires_existing_file(vault_dir):
    result = json.loads(vault_append("missing.md", "x", heading="## Track 1"))
    assert "error" in result
    assert not (vault_dir / "missing.md").exists()


def test_append_with_unknown_heading_errors(vault_dir):
    vault_write("doc.md", DOC)
    result = json.loads(vault_append("doc.md", "x", heading="## Nope"))
    assert "error" in result
    assert "not found" in result["error"].lower()


# --- vault_edit_section ------------------------------------------------------

def test_edit_section_replaces_only_within_scoped_heading(vault_dir):
    doc = "## A\n\nshared text\n\n## B\n\nshared text\n"
    vault_write("doc.md", doc)

    result = json.loads(vault_edit_section(
        "doc.md", "## A", [{"old_text": "shared text", "new_text": "changed"}]
    ))
    assert result["changed"] is True

    content = (vault_dir / "doc.md").read_text()
    assert content.count("shared text") == 1
    assert content.count("changed") == 1
    assert "## A\n\nchanged" in content


def test_edit_section_dry_run_does_not_write(vault_dir):
    vault_write("doc.md", DOC)
    before = (vault_dir / "doc.md").read_text()

    result = json.loads(vault_edit_section(
        "doc.md", "## Track 1",
        [{"old_text": "Some notes about track 1.", "new_text": "Edited."}],
        dry_run=True,
    ))
    assert result["dry_run"] is True
    assert "Edited." in result["diff"]
    assert (vault_dir / "doc.md").read_text() == before


def test_edit_section_unknown_heading_errors(vault_dir):
    vault_write("doc.md", DOC)
    result = json.loads(vault_edit_section(
        "doc.md", "## Nope", [{"old_text": "x", "new_text": "y"}]
    ))
    assert "error" in result


def test_edit_section_ambiguous_match_in_section_errors(vault_dir):
    doc = "## A\n\nfoo foo\n\n## B\n\nbar\n"
    vault_write("doc.md", doc)
    result = json.loads(vault_edit_section(
        "doc.md", "## A", [{"old_text": "foo", "new_text": "baz"}]
    ))
    assert "error" in result
    assert "found 2 matches" in result["error"]


def test_edit_section_replace_all_stays_within_the_section(vault_dir):
    doc = "## A\n\nfoo foo\n\n## B\n\nfoo\n"
    vault_write("doc.md", doc)
    result = json.loads(vault_edit_section(
        "doc.md", "## A", [{"old_text": "foo", "new_text": "baz", "replace_all": True}]
    ))
    assert result["changed"] is True
    assert (vault_dir / "doc.md").read_text() == "## A\n\nbaz baz\n\n## B\n\nfoo\n"


def test_edit_section_replace_all_still_errors_on_zero_matches(vault_dir):
    vault_write("doc.md", "## A\n\nfoo\n\n## B\n\nbar\n")
    result = json.loads(vault_edit_section(
        "doc.md", "## A", [{"old_text": "bar", "new_text": "x", "replace_all": True}]
    ))
    assert "found 0 matches" in result["error"]


def test_edit_section_rejects_empty_old_text(vault_dir):
    vault_write("doc.md", DOC)
    before = (vault_dir / "doc.md").read_text()
    result = json.loads(vault_edit_section(
        "doc.md", "## Track 1", [{"old_text": "", "new_text": "x"}]
    ))
    assert "no old_text" in result["error"]
    assert (vault_dir / "doc.md").read_text() == before


def test_a_failed_edit_leaves_earlier_edits_unwritten(vault_dir):
    vault_write("doc.md", DOC)
    before = (vault_dir / "doc.md").read_text()
    result = json.loads(vault_edit_section("doc.md", "## Track 1", [
        {"old_text": "Some notes about track 1.", "new_text": "Edited."},
        {"old_text": "not in this section", "new_text": "x"},
    ]))
    assert "error" in result
    assert (vault_dir / "doc.md").read_text() == before


def test_heading_tools_refuse_a_path_outside_the_vault(vault_dir):
    assert "error" in json.loads(vault_append("../escape.md", "x", heading="## A"))
    assert "error" in json.loads(vault_edit_section(
        "../escape.md", "## A", [{"old_text": "x", "new_text": "y"}]
    ))


# --- wiring: the registered tools, not just the helpers ----------------------------------

def call_tool(name: str, arguments: dict) -> dict:
    result = asyncio.run(server.mcp.call_tool(name, arguments))
    if isinstance(result, tuple):
        result = result[0]
    return json.loads("".join(getattr(block, "text", "") for block in result))


def test_registered_edit_section_tool_applies_a_scoped_edit(vault_dir):
    (vault_dir / "doc.md").write_text("## A\n\nshared\n\n## B\n\nshared\n", encoding="utf-8")
    result = call_tool("vault_edit_section", {
        "path": "doc.md", "heading": "## B",
        "edits": [{"old_text": "shared", "new_text": "changed"}],
    })
    assert result["changed"] is True
    assert (vault_dir / "doc.md").read_text() == "## A\n\nshared\n\n## B\n\nchanged\n"


def test_registered_edit_section_tool_rejects_unknown_fields(vault_dir):
    (vault_dir / "doc.md").write_text(DOC, encoding="utf-8")
    with pytest.raises(Exception):
        call_tool("vault_edit_section", {
            "path": "doc.md", "heading": "## Track 1",
            "edits": [{"old_text": "Some", "new_text": "x", "bogus": 1}],
        })


def test_registered_append_tool_honors_heading(vault_dir):
    (vault_dir / "doc.md").write_text(DOC, encoding="utf-8")
    result = call_tool("vault_append", {"path": "doc.md", "content": "Added.", "heading": "## Track 1"})
    assert result["changed"] is True
    content = (vault_dir / "doc.md").read_text()
    assert content.index("Added.") < content.index("## Track 2")


def test_section_edit_is_recorded_in_the_audit_log(vault_dir, tmp_path, monkeypatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(log_path))
    token = context.set_request_context(principal="tok", request_id="r1", client="pytest")
    try:
        (vault_dir / "doc.md").write_text(DOC, encoding="utf-8")
        server.vault_edit_section(
            "doc.md", "## Track 1", [{"old_text": "Some notes about track 1.", "new_text": "Edited."}]
        )
    finally:
        context.reset_request_context(token)
    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line]
    assert [(r["operation"], r["target_path"], r["operation_status"]) for r in records] == [
        ("vault_edit_section", "doc.md", "success")
    ]
    assert records[0]["checksum_before"] != records[0]["checksum_after"]
