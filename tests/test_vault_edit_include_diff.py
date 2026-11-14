"""vault_edit's include_diff flag: leave the diff out of an applied edit's result.

The diff is most of the reply to a small edit, and a caller that already knows what it
sent has no use for it. `include_diff: false` leaves it out. The default stays true, so
every existing call gets the same reply as before, and a dry run always returns its diff,
because showing the change is what a dry run is for. Errors keep their empty "diff" key
whatever the flag says.

Every case goes through the registered tool, like test_vault_edit_replace_all.py, so the
input model, the audit wrapper and the write path are all in the picture.
"""

import asyncio
import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from obsidian_vault_mcp import config, context, server, write_events

NOTE = """---
status: active
---

Der Zaehlerstand steht im Protokoll. Der Zaehlerstand wird monatlich gemeldet.
Ein dritter Satz nennt den Zaehlerstand erneut.
"""

ONE_WORD = {"old_text": "dritter", "new_text": "vierter"}
APPLIED_KEYS = ["path", "changed", "dry_run", "diff", "edits_applied", "replacements", "size"]


def call_tool(name: str, arguments: dict) -> dict:
    result = asyncio.run(server.mcp.call_tool(name, arguments))
    if isinstance(result, tuple):
        result = result[0]
    return json.loads("".join(getattr(block, "text", "") for block in result))


def edit(path: str, edits: list[dict], **flags) -> dict:
    return call_tool("vault_edit", {"path": path, "edits": edits, **flags})


def without(result: dict, *keys: str) -> dict:
    return {key: value for key, value in result.items() if key not in keys}


@pytest.fixture
def note(vault_dir):
    target = vault_dir / "messung.md"
    target.write_text(NOTE, encoding="utf-8")
    return target


@pytest.fixture
def twin_notes(vault_dir):
    """Two byte-identical notes, so one can be edited each way and the outcomes compared."""
    first, second = vault_dir / "eins.md", vault_dir / "zwei.md"
    first.write_text(NOTE, encoding="utf-8")
    second.write_text(NOTE, encoding="utf-8")
    return first, second


@pytest.fixture
def events():
    captured = []
    write_events.register_write_listener(lambda op, paths: captured.append((op, paths)))
    yield captured
    write_events._write_listeners.clear()


@pytest.fixture
def audit_log(tmp_path, monkeypatch, vault_dir):
    log_path = tmp_path / "audit" / "mutations.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(log_path))
    token = context.set_request_context(principal="test-principal", request_id="req-1", client="pytest")
    yield log_path
    context.reset_request_context(token)


def test_the_default_still_returns_the_diff(twin_notes):
    """Negative control: without the flag the reply is what it was before, diff included,
    and it is the same reply as include_diff=true."""
    default = edit("eins.md", [ONE_WORD])
    explicit = edit("zwei.md", [ONE_WORD], include_diff=True)

    assert list(default) == APPLIED_KEYS, default
    assert "-Ein dritter Satz nennt den Zaehlerstand erneut." in default["diff"]
    assert "+Ein vierter Satz nennt den Zaehlerstand erneut." in default["diff"]
    assert default["diff"].startswith("--- eins.md before\n+++ eins.md after\n")
    assert without(default, "path", "diff") == without(explicit, "path", "diff")
    assert default["diff"].replace("eins.md", "zwei.md") == explicit["diff"]


def test_include_diff_false_leaves_only_the_diff_out(note):
    result = edit("messung.md", [ONE_WORD], include_diff=False)

    assert "diff" not in result, result
    assert list(result) == [key for key in APPLIED_KEYS if key != "diff"]
    assert result["path"] == "messung.md"
    assert result["changed"] is True
    assert result["dry_run"] is False
    assert result["edits_applied"] == 1
    assert result["replacements"] == 1
    assert result["size"] == len(note.read_bytes())
    assert note.read_text(encoding="utf-8") == NOTE.replace("dritter", "vierter")


def test_the_same_bytes_are_written_either_way(twin_notes):
    first, second = twin_notes

    with_diff = edit("eins.md", [ONE_WORD], include_diff=True)
    without_diff = edit("zwei.md", [ONE_WORD], include_diff=False)

    assert first.read_bytes() == second.read_bytes()
    assert first.read_text(encoding="utf-8") == NOTE.replace("dritter", "vierter")
    assert with_diff["size"] == without_diff["size"] == len(second.read_bytes())


def test_a_dry_run_still_returns_its_diff_and_writes_nothing(note):
    asked_for_it = edit("messung.md", [ONE_WORD], dry_run=True)
    result = edit("messung.md", [ONE_WORD], dry_run=True, include_diff=False)

    assert result["dry_run"] is True and result["changed"] is False
    assert "+Ein vierter Satz nennt den Zaehlerstand erneut." in result["diff"], result
    assert result == asked_for_it
    assert note.read_text(encoding="utf-8") == NOTE


@pytest.mark.parametrize(
    "edits",
    [
        pytest.param([{"old_text": "kommt nicht vor", "new_text": "x"}], id="no-match"),
        pytest.param([{"old_text": "Zaehlerstand", "new_text": "Zählerstand"}], id="ambiguous-match"),
    ],
)
def test_errors_are_the_same_with_the_flag_on_or_off(note, edits):
    with_diff = edit("messung.md", edits, include_diff=True)
    without_diff = edit("messung.md", edits, include_diff=False)

    assert "error" in with_diff, with_diff
    assert with_diff["diff"] == "" and without_diff["diff"] == ""
    assert without_diff == with_diff
    assert note.read_text(encoding="utf-8") == NOTE


def test_a_missing_file_is_the_same_with_the_flag_on_or_off(vault_dir):
    with_diff = edit("fehlt.md", [ONE_WORD], include_diff=True)
    without_diff = edit("fehlt.md", [ONE_WORD], include_diff=False)

    assert "File not found" in with_diff["error"], with_diff
    assert with_diff["diff"] == "" and without_diff["diff"] == ""
    assert without_diff == with_diff
    assert not (vault_dir / "fehlt.md").exists()


@pytest.mark.parametrize(
    "value",
    [pytest.param("maybe", id="string"), pytest.param(["x"], id="list"), pytest.param(2, id="number")],
)
def test_a_value_that_is_not_a_boolean_is_refused(note, value):
    with pytest.raises(ToolError) as excinfo:
        edit("messung.md", [ONE_WORD], include_diff=value)

    assert "include_diff" in str(excinfo.value)
    assert note.read_text(encoding="utf-8") == NOTE


def test_the_flag_is_in_the_tool_schema_as_a_boolean_defaulting_to_true(vault_dir):
    tool = next(t for t in asyncio.run(server.mcp.list_tools()) if t.name == "vault_edit")
    schema = tool.inputSchema

    assert schema["properties"]["include_diff"]["type"] == "boolean"
    assert schema["properties"]["include_diff"]["default"] is True
    assert "include_diff" not in schema["required"]
    assert "include_diff=false" in tool.description


def test_with_replace_all_every_occurrence_is_counted_and_no_diff_is_returned(note):
    result = edit(
        "messung.md",
        [{"old_text": "Zaehlerstand", "new_text": "Zählerstand", "replace_all": True}],
        include_diff=False,
    )

    assert "diff" not in result, result
    assert result["replacements"] == 3
    assert result["edits_applied"] == 1
    assert note.read_text(encoding="utf-8").count("Zählerstand") == 3


def test_an_edit_that_changes_nothing_reports_no_change_and_no_diff(note):
    same = {"old_text": "dritter", "new_text": "dritter"}

    with_diff = edit("messung.md", [same], include_diff=True)
    without_diff = edit("messung.md", [same], include_diff=False)

    assert with_diff["changed"] is False and with_diff["diff"] == ""
    assert without_diff["changed"] is False
    assert "diff" not in without_diff, without_diff
    assert without_diff == without(with_diff, "diff")
    assert note.read_text(encoding="utf-8") == NOTE


def test_the_write_listener_fires_the_same_either_way(twin_notes, events):
    edit("eins.md", [ONE_WORD], include_diff=True)
    edit("zwei.md", [ONE_WORD], include_diff=False)

    assert events == [("updated", ["eins.md"]), ("updated", ["zwei.md"])]


def test_the_audit_record_is_the_same_either_way(twin_notes, audit_log):
    edit("eins.md", [ONE_WORD], include_diff=True)
    edit("zwei.md", [ONE_WORD], include_diff=False)

    with_diff, without_diff = [
        json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines() if line
    ]
    assert with_diff["operation"] == without_diff["operation"] == "vault_edit"
    assert (with_diff["target_path"], without_diff["target_path"]) == ("eins.md", "zwei.md")
    assert with_diff["operation_status"] == without_diff["operation_status"] == "success"
    assert with_diff["checksum_after"] != with_diff["checksum_before"]
    assert without(without_diff, "timestamp", "target_path") == without(with_diff, "timestamp", "target_path")
