"""The six core mutation tools fire write events at their success path.

Semantics under test (from #58): created-vs-updated distinguished; vault_move is a
single "moved" with both paths; a batch fires once with only the successfully-written
paths; vault_edit does not fire on a dry-run or a no-change edit; delete fires only on
a confirmed success; a failed/aborted write never fires.
"""

import json

import pytest

from obsidian_vault_mcp import write_events
from obsidian_vault_mcp.tools.write import (
    vault_append,
    vault_batch_frontmatter_update,
    vault_edit,
    vault_write,
)
from obsidian_vault_mcp.tools.manage import vault_delete, vault_move


@pytest.fixture
def events():
    """Capture (operation, paths) events and isolate the process-global registry."""
    write_events._write_listeners.clear()
    captured = []
    write_events.register_write_listener(lambda op, paths: captured.append((op, paths)))
    yield captured
    write_events._write_listeners.clear()


# --- vault_write ---

def test_vault_write_new_file_fires_created(vault_dir, events):
    vault_write("fresh.md", "hello")
    assert events == [("created", ["fresh.md"])]


def test_vault_write_existing_file_fires_updated(vault_dir, events):
    vault_write("test-note.md", "changed body")
    assert events == [("updated", ["test-note.md"])]


def test_vault_write_invalid_path_does_not_fire(vault_dir, events):
    result = json.loads(vault_write("../escape.md", "x"))
    assert "error" in result
    assert events == []


# --- vault_edit ---

def test_vault_edit_applied_change_fires_updated(vault_dir, events):
    vault_edit("test-note.md", [{"old_text": "test note", "new_text": "edited note"}])
    assert events == [("updated", ["test-note.md"])]


def test_vault_edit_dry_run_does_not_fire(vault_dir, events):
    vault_edit(
        "test-note.md",
        [{"old_text": "test note", "new_text": "edited note"}],
        dry_run=True,
    )
    assert events == []


def test_vault_edit_no_change_does_not_fire(vault_dir, events):
    """old_text == new_text leaves the file untouched, so nothing is written."""
    result = json.loads(vault_edit(
        "test-note.md", [{"old_text": "test note", "new_text": "test note"}]
    ))
    assert result["changed"] is False
    assert events == []


def test_vault_edit_failed_match_does_not_fire(vault_dir, events):
    json.loads(vault_edit(
        "test-note.md", [{"old_text": "nope-not-present", "new_text": "x"}]
    ))
    assert events == []


# --- vault_append ---

def test_vault_append_existing_fires_updated(vault_dir, events):
    vault_append("no-frontmatter.md", "more text")
    assert events == [("updated", ["no-frontmatter.md"])]


def test_vault_append_new_file_fires_created(vault_dir, events):
    vault_append("new/appended.md", "brand new")
    assert events == [("created", ["new/appended.md"])]


def test_vault_append_no_change_does_not_fire(vault_dir, events):
    """Appending empty content to an existing file writes nothing."""
    result = json.loads(vault_append("no-frontmatter.md", ""))
    assert result["changed"] is False
    assert events == []


# --- vault_batch_frontmatter_update ---

def test_batch_fires_once_with_only_successful_paths(vault_dir, events):
    vault_batch_frontmatter_update([
        {"path": "test-note.md", "fields": {"reviewed": True}},
        {"path": "does-not-exist.md", "fields": {"reviewed": True}},
        {"path": "subfolder/nested-note.md", "fields": {"reviewed": True}},
    ])
    assert events == [
        ("updated", ["test-note.md", "subfolder/nested-note.md"]),
    ]


def test_batch_all_failed_does_not_fire(vault_dir, events):
    vault_batch_frontmatter_update([
        {"path": "missing-a.md", "fields": {"x": 1}},
        {"path": "missing-b.md", "fields": {"x": 1}},
    ])
    assert events == []


# --- vault_move ---

def test_vault_move_fires_one_moved_with_both_paths(vault_dir, events):
    vault_move("test-note.md", "moved-note.md")
    assert events == [("moved", ["test-note.md", "moved-note.md"])]


def test_vault_move_failure_does_not_fire(vault_dir, events):
    json.loads(vault_move("does-not-exist.md", "anywhere.md"))
    assert events == []


# --- vault_delete ---

def test_vault_delete_confirmed_fires_deleted(vault_dir, events):
    vault_delete("test-note.md", confirm=True)
    assert events == [("deleted", ["test-note.md"])]


def test_vault_delete_without_confirm_does_not_fire(vault_dir, events):
    vault_delete("test-note.md", confirm=False)
    assert events == []


def test_vault_delete_missing_file_does_not_fire(vault_dir, events):
    json.loads(vault_delete("not-here.md", confirm=True))
    assert events == []
