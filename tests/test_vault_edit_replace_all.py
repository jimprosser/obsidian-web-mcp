"""vault_edit's opt-in all-occurrences mode (#83).

The default stays exactly-once, because that is what makes an edit safe to send blind.
`replace_all: true` is the opt-in for renaming a term across a note in one call.

Every case goes through the registered tool, so the pydantic model, the alias
normalization and the write path are all in the picture, not just the helper.
"""

import asyncio
import json

import pytest

from obsidian_vault_mcp import server

NOTE = """---
status: active
---

Der Zaehlerstand steht im Protokoll. Der Zaehlerstand wird monatlich gemeldet.
Ein dritter Satz nennt den Zaehlerstand erneut.
"""


def call_tool(name: str, arguments: dict) -> dict:
    result = asyncio.run(server.mcp.call_tool(name, arguments))
    if isinstance(result, tuple):
        result = result[0]
    return json.loads("".join(getattr(block, "text", "") for block in result))


@pytest.fixture
def note(vault_dir):
    target = vault_dir / "messung.md"
    target.write_text(NOTE, encoding="utf-8")
    return target


def test_the_default_still_refuses_a_repeated_match(note):
    """The negative control for everything below: the term really is in there three times."""
    assert note.read_text(encoding="utf-8").count("Zaehlerstand") == 3

    result = call_tool("vault_edit", {"path": "messung.md", "edits": [{"old_text": "Zaehlerstand", "new_text": "Zählerstand"}]})

    assert "error" in result and "exactly once" in result["error"], result
    assert result["changed"] is False
    assert note.read_text(encoding="utf-8") == NOTE


def test_replace_all_replaces_every_occurrence_and_reports_the_count(note):
    result = call_tool(
        "vault_edit",
        {"path": "messung.md", "edits": [{"old_text": "Zaehlerstand", "new_text": "Zählerstand", "replace_all": True}]},
    )

    assert "error" not in result, result
    assert result["changed"] is True
    assert result["replacements"] == 3
    assert result["edits_applied"] == 1
    body = note.read_text(encoding="utf-8")
    assert "Zaehlerstand" not in body
    assert body.count("Zählerstand") == 3


def test_a_single_occurrence_works_with_replace_all_too(note):
    result = call_tool(
        "vault_edit",
        {"path": "messung.md", "edits": [{"old_text": "dritter", "new_text": "vierter", "replace_all": True}]},
    )

    assert result["replacements"] == 1, result
    assert "vierter Satz" in note.read_text(encoding="utf-8")


def test_zero_matches_is_still_an_error_with_the_near_miss_hint(note):
    result = call_tool(
        "vault_edit",
        {"path": "messung.md", "edits": [{"old_text": "Zahlerstand steht im Protokol", "new_text": "x", "replace_all": True}]},
    )

    assert "error" in result and "at least once" in result["error"], result
    assert result["near_miss"]["line_number"] == 5, result
    assert note.read_text(encoding="utf-8") == NOTE


def test_all_or_nothing_across_the_list(note):
    """A later edit that cannot apply leaves the earlier one unwritten, as before."""
    result = call_tool(
        "vault_edit",
        {
            "path": "messung.md",
            "edits": [
                {"old_text": "Zaehlerstand", "new_text": "Zählerstand", "replace_all": True},
                {"old_text": "kommt nicht vor", "new_text": "x"},
            ],
        },
    )

    assert "error" in result, result
    assert note.read_text(encoding="utf-8") == NOTE


def test_mixed_list_applies_in_order(note):
    result = call_tool(
        "vault_edit",
        {
            "path": "messung.md",
            "edits": [
                {"old_text": "Zaehlerstand", "new_text": "Zählerstand", "replace_all": True},
                {"old_text": "Ein dritter", "new_text": "Ein letzter"},
            ],
        },
    )

    body = note.read_text(encoding="utf-8")
    assert result["replacements"] == 4, result
    assert body.count("Zählerstand") == 3 and "Ein letzter" in body


def test_dry_run_shows_the_full_diff_and_writes_nothing(note):
    result = call_tool(
        "vault_edit",
        {
            "path": "messung.md",
            "edits": [{"old_text": "Zaehlerstand", "new_text": "Zählerstand", "replace_all": True}],
            "dry_run": True,
        },
    )

    assert result["dry_run"] is True and result["changed"] is False
    assert result["match_counts"][0] == {"index": 0, "replace_all": True, "count": 3}
    assert result["replacements"] == 3
    assert result["diff"].count("+Der Zählerstand") == 1
    assert result["diff"].count("Zählerstand") == 3, result["diff"]
    assert note.read_text(encoding="utf-8") == NOTE


def test_dry_run_predicts_the_apply_for_a_chained_pair(note):
    edits = [
        {"old_text": "Zaehlerstand", "new_text": "Zählerstand", "replace_all": True},
        {"old_text": "Zählerstand wird", "new_text": "Zählerstand wird immer"},
    ]

    preview = call_tool("vault_edit", {"path": "messung.md", "edits": edits, "dry_run": True})
    applied = call_tool("vault_edit", {"path": "messung.md", "edits": edits})

    assert preview["replacements"] == applied["replacements"] == 4
    assert preview["diff"] == applied["diff"]


def test_an_empty_old_text_is_still_refused(note):
    """With replace-all an empty match string would interleave new_text between every
    character. The model's min_length=1 is what stops it."""
    with pytest.raises(Exception) as excinfo:
        call_tool("vault_edit", {"path": "messung.md", "edits": [{"old_text": "", "new_text": "x", "replace_all": True}]})

    assert "old_text" in str(excinfo.value)
    assert note.read_text(encoding="utf-8") == NOTE


def test_the_flag_is_in_the_tool_schema(vault_dir):
    tool = server.mcp._tool_manager.get_tool("vault_edit")
    schema = json.dumps(tool.parameters)

    assert "replace_all" in schema
