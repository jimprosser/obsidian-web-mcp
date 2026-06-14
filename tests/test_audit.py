"""Tests for the append-only JSONL audit log (VAULT_AUDIT_LOG_PATH).

The vault_dir fixture (conftest) points the server at a temp vault. These tests drive the
server-level tool functions directly -- the same callables FastMCP registers -- so the
_run_audited wrapper is exercised end to end. The bearer middleware is not in the loop
here, so the authenticated principal is bound manually via context.set_request_context.
"""

import json

import pytest

from obsidian_vault_mcp import audit, config, context, server

PRINCIPAL = "test-bearer-token-abc123"
EXPECTED_HASH = __import__("hashlib").sha256(PRINCIPAL.encode("utf-8")).hexdigest()


@pytest.fixture
def audit_log(vault_dir, tmp_path, monkeypatch):
    """Enable auditing to a temp log file with a bound principal; isolate global state."""
    log_path = tmp_path / "audit" / "mutations.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(log_path))
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", False)
    token = context.set_request_context(principal=PRINCIPAL, request_id="req-1", client="pytest")
    yield log_path
    context.reset_request_context(token)


def _records(log_path):
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line]


# --- off by default ---

def test_audit_off_by_default(vault_dir, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", "")
    log_path = tmp_path / "should-not-exist.jsonl"
    result = json.loads(server.vault_write("note.md", "body"))
    assert result["path"] == "note.md"
    assert not log_path.exists()
    assert audit.should_audit_operation("vault_write") is False


# --- mutations ---

def test_mutation_writes_record_with_required_fields(audit_log):
    server.vault_write("audited.md", "hello audit")
    records = _records(audit_log)
    assert len(records) == 1
    rec = records[0]
    for field in (
        "timestamp", "token_id_hash", "client_id", "operation", "target_path",
        "size_before", "size_after", "checksum_before", "checksum_after",
        "request_id", "operation_status", "error",
    ):
        assert field in rec
    assert rec["operation"] == "vault_write"
    assert rec["target_path"] == "audited.md"
    assert rec["operation_status"] == "success"
    assert rec["size_before"] is None          # new file
    assert rec["size_after"] == len(b"hello audit")
    assert rec["checksum_after"] is not None


def test_raw_token_never_written_only_hash(audit_log):
    server.vault_write("audited.md", "secret content")
    raw = audit_log.read_text(encoding="utf-8")
    assert PRINCIPAL not in raw
    assert _records(audit_log)[0]["token_id_hash"] == EXPECTED_HASH
    assert _records(audit_log)[0]["client_id"] == "pytest"


def test_overwrite_captures_before_and_after(audit_log):
    server.vault_write("note.md", "first version")
    server.vault_write("note.md", "second, longer version")
    rec = _records(audit_log)[-1]
    assert rec["size_before"] == len(b"first version")
    assert rec["size_after"] == len(b"second, longer version")
    assert rec["checksum_before"] != rec["checksum_after"]


def test_mutation_error_recorded(audit_log):
    # A path that escapes the vault returns an error payload (a mutation attempt).
    result = json.loads(server.vault_write("../escape.md", "x"))
    assert "error" in result
    rec = _records(audit_log)[-1]
    assert rec["operation"] == "vault_write"
    assert rec["operation_status"] == "error"
    assert rec["error"]


def test_move_records_destination(audit_log):
    server.vault_write("src.md", "movable")
    server.vault_move("src.md", "dst.md")
    rec = _records(audit_log)[-1]
    assert rec["operation"] == "vault_move"
    assert rec["target_path"] == "dst.md"
    assert rec["size_after"] == len(b"movable")


# --- reads (opt-in) ---

def test_reads_not_logged_by_default(audit_log):
    server.vault_read("test-note.md")
    assert _records(audit_log) == []
    assert audit.should_audit_operation("vault_read") is False


def test_reads_logged_when_enabled(audit_log, monkeypatch):
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", True)
    server.vault_read("test-note.md")
    rec = _records(audit_log)[-1]
    assert rec["operation"] == "vault_read"
    assert rec["target_path"] == "test-note.md"
    assert rec["checksum_before"] is not None   # captured as read


# --- failure isolation ---

def test_audit_write_failure_does_not_break_tool(vault_dir, monkeypatch):
    # Parent of the log path is an existing FILE, so mkdir/open fails on every write.
    bad = vault_dir / "test-note.md" / "audit.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(bad))
    assert audit.audit_path_writable() is False
    token = context.set_request_context(principal=PRINCIPAL, request_id="r", client="c")
    try:
        result = json.loads(server.vault_write("still-works.md", "body"))
        assert result["created"] is True        # the write itself succeeded despite audit failing
    finally:
        context.reset_request_context(token)


# --- in-vault audit log rejected (#2 integrity) ---

def test_audit_path_inside_vault_detected(vault_dir, monkeypatch):
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(vault_dir / "audit.jsonl"))
    assert audit.audit_path_inside_vault() is True
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(vault_dir / "subfolder" / "a.jsonl"))
    assert audit.audit_path_inside_vault() is True


def test_audit_path_outside_vault_ok(vault_dir, tmp_path, monkeypatch):
    # tmp_path is the vault's parent, so a sibling dir is outside the vault.
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(tmp_path / "outside" / "audit.jsonl"))
    assert audit.audit_path_inside_vault() is False


# --- writability ---

def test_path_writable_checks(vault_dir, tmp_path, monkeypatch):
    good = tmp_path / "ok.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(good))
    assert audit.audit_path_writable() is True
    bad = vault_dir / "test-note.md" / "nope.jsonl"   # parent is a file
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(bad))
    assert audit.audit_path_writable() is False


# --- snapshot safety ---

def test_snapshot_path_stays_in_vault(vault_dir):
    assert audit.snapshot_path("../outside.md") == {"size": None, "checksum": None}
    assert audit.snapshot_path("does-not-exist.md") == {"size": None, "checksum": None}
    snap = audit.snapshot_path("test-note.md")
    assert snap["size"] > 0 and snap["checksum"]


# --- wiring: tools stay registered (wrapper preserved the schema) ---

@pytest.mark.parametrize("name", [
    "vault_write", "vault_edit", "vault_append", "vault_move", "vault_delete",
    "vault_read", "vault_search", "vault_canvas_add_node", "vault_daily_note_append",
])
def test_audited_tools_still_registered(vault_dir, name):
    assert server.mcp._tool_manager.get_tool(name) is not None


# --- batch: one record per file with correct per-file status (#3) ---

def test_batch_emits_one_record_per_file_with_status(audit_log):
    server.vault_write("a.md", "---\nx: 1\n---\nbody")
    # a.md exists, missing.md does not -> partial failure within one batch call
    updates = [
        {"path": "a.md", "fields": {"status": "done"}},
        {"path": "missing.md", "fields": {"status": "done"}},
    ]
    server.vault_batch_frontmatter_update(updates)
    recs = [r for r in _records(audit_log) if r["operation"] == "vault_batch_frontmatter_update"]
    assert len(recs) == 2                      # one record per file, not one for the call
    by_path = {r["target_path"]: r for r in recs}
    assert by_path["a.md"]["operation_status"] == "success"
    assert by_path["a.md"]["checksum_after"] is not None   # real snapshot, not null
    assert by_path["missing.md"]["operation_status"] == "error"   # partial failure surfaced
    assert by_path["missing.md"]["error"]


# --- dry-run edit is not recorded as a mutation (non-blocking item) ---

def test_dry_run_edit_not_audited(audit_log):
    server.vault_write("edit.md", "alpha beta")
    before = len(_records(audit_log))
    server.vault_edit("edit.md", [{"old_text": "alpha", "new_text": "ALPHA"}], dry_run=True)
    assert len(_records(audit_log)) == before          # dry run wrote nothing, logged nothing
    server.vault_edit("edit.md", [{"old_text": "alpha", "new_text": "ALPHA"}])
    assert len(_records(audit_log)) == before + 1       # the real edit IS audited


def test_daily_append_captures_before_snapshot(audit_log, monkeypatch):
    monkeypatch.setattr(config, "VAULT_DAILY_NOTES_FOLDER", "")
    server.vault_daily_note_append("first line")
    server.vault_daily_note_append("second line")
    recs = [r for r in _records(audit_log) if r["operation"] == "vault_daily_note_append"]
    assert recs[-1]["size_before"] is not None          # before-snapshot now captured
