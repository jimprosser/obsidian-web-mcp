"""Extension tools can join the audit log (#91).

Before this, should_audit_operation answered False for any operation name the host did not
ship with, so an extension's tools stayed out of the log however the operator configured
it, and each extension had to re-implement the wrapper around its writes by hand.

The tools here are registered the way an extension registers them: an Extension whose
register_tools adds @mcp.tool functions, called through the FastMCP registration a client
reaches. Each case is paired with its negative control: the same tool without
register_audit_operation, which must leave no record.
"""

import asyncio
import json

import pytest

from obsidian_vault_mcp import audit, config, server
from obsidian_vault_mcp.audit import register_audit_operation, run_audited
from obsidian_vault_mcp.extensions import Extension
from obsidian_vault_mcp.vault import resolve_vault_path, write_file_atomic


class AuditedExtension(Extension):
    """Three tools: a registered mutation, a registered read, and an unregistered write."""

    def register_tools(self, mcp):
        @mcp.tool(name="ext_audit_write")
        def ext_audit_write(path: str, content: str) -> str:
            def work():
                is_new, size = write_file_atomic(path, content)
                return json.dumps({"path": path, "created": is_new, "size": size})

            return run_audited("ext_audit_write", work, path=path)

        @mcp.tool(name="ext_audit_read")
        def ext_audit_read(path: str) -> str:
            def work():
                return json.dumps({"path": path, "size": resolve_vault_path(path).stat().st_size})

            return run_audited("ext_audit_read", work, path=path)

        @mcp.tool(name="ext_audit_unregistered")
        def ext_audit_unregistered(path: str, content: str) -> str:
            def work():
                write_file_atomic(path, content)
                return json.dumps({"path": path})

            return run_audited("ext_audit_unregistered", work, path=path)


@pytest.fixture(scope="module", autouse=True)
def extension_tools():
    AuditedExtension().register_tools(server.mcp)
    register_audit_operation("ext_audit_write", kind="mutation")
    register_audit_operation("ext_audit_read", kind="read")
    yield
    audit._registered_operations.pop("ext_audit_write", None)
    audit._registered_operations.pop("ext_audit_read", None)


@pytest.fixture
def audit_log(vault_dir, tmp_path, monkeypatch):
    path = tmp_path / "audit" / "audit.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(path))
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", False)

    def records():
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    return records


def call_tool(name: str, arguments: dict) -> dict:
    result = asyncio.run(server.mcp.call_tool(name, arguments))
    if isinstance(result, tuple):
        result = result[0]
    return json.loads("".join(getattr(block, "text", "") for block in result))


# --- mutations ------------------------------------------------------------------------

def test_a_registered_mutation_is_recorded_with_before_and_after(vault_dir, audit_log):
    (vault_dir / "ext.md").write_bytes(b"alt\n")

    call_tool("ext_audit_write", {"path": "ext.md", "content": "neu und länger\n"})

    records = [r for r in audit_log() if r["operation"] == "ext_audit_write"]
    assert len(records) == 1, audit_log()
    record = records[0]
    assert record["target_path"] == "ext.md" and record["operation_status"] == "success"
    assert record["size_before"] == len("alt\n".encode("utf-8"))
    assert record["size_after"] == len("neu und länger\n".encode("utf-8"))
    assert record["checksum_before"] != record["checksum_after"]


def test_an_unregistered_tool_leaves_no_record(vault_dir, audit_log):
    """Negative control: the wrapper alone is not enough, the name must be declared."""
    result = call_tool("ext_audit_unregistered", {"path": "still.md", "content": "x\n"})

    assert (vault_dir / "still.md").exists(), f"negative control: the write did not happen: {result}"
    assert audit_log() == []


def test_a_registered_mutation_is_silent_with_auditing_off(vault_dir, audit_log, monkeypatch):
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", "")
    monkeypatch.setattr(audit, "snapshot_path", lambda path: pytest.fail("hashed a file with auditing off"))

    call_tool("ext_audit_write", {"path": "aus.md", "content": "x\n"})

    assert (vault_dir / "aus.md").exists()
    assert audit_log() == []


def test_an_exception_in_the_tool_is_recorded_as_an_error(vault_dir, audit_log):
    def broken():
        raise RuntimeError("disk full")

    with pytest.raises(RuntimeError):
        run_audited("ext_audit_write", broken, path="kaputt.md")

    records = audit_log()
    assert len(records) == 1 and records[0]["operation_status"] == "error", records


# --- reads ----------------------------------------------------------------------------

def test_a_registered_read_is_silent_unless_reads_are_included(vault_dir, audit_log, monkeypatch):
    (vault_dir / "lesen.md").write_bytes(b"inhalt\n")

    call_tool("ext_audit_read", {"path": "lesen.md"})
    assert audit_log() == [], "a read was recorded with VAULT_AUDIT_LOG_INCLUDE_READS off"

    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", True)
    call_tool("ext_audit_read", {"path": "lesen.md"})

    records = [r for r in audit_log() if r["operation"] == "ext_audit_read"]
    assert len(records) == 1, audit_log()
    assert records[0]["target_path"] == "lesen.md"
    assert records[0]["size_before"] == len("inhalt\n")


# --- the registry itself --------------------------------------------------------------

def test_kinds_are_reported(vault_dir):
    assert audit.operation_kind("ext_audit_write") == "mutation"
    assert audit.operation_kind("ext_audit_read") == "read"
    assert audit.operation_kind("vault_write") == "mutation"
    assert audit.operation_kind("vault_read") == "read"
    assert audit.operation_kind("ext_audit_unregistered") is None


def test_registering_the_same_kind_twice_is_a_no_op():
    register_audit_operation("ext_audit_write", kind="mutation")

    assert audit.operation_kind("ext_audit_write") == "mutation"


@pytest.mark.parametrize(
    "name,kind,message",
    [
        ("ext_audit_write", "read", "already registered"),
        ("vault_write", "read", "built-in"),
        ("vault_read", "read", "built-in"),
        ("", "mutation", "non-empty"),
        ("   ", "mutation", "non-empty"),
        ("ext_other", "write", "kind"),
    ],
)
def test_a_bad_registration_is_refused(name, kind, message):
    with pytest.raises(ValueError, match=message):
        register_audit_operation(name, kind=kind)


def test_built_in_tools_still_go_through_the_same_wrapper(vault_dir, audit_log):
    """The wrapper moved to audit.py under a public name; the built-ins must keep using it."""
    call_tool("vault_write", {"path": "eingebaut.md", "content": "x\n"})

    records = [r for r in audit_log() if r["operation"] == "vault_write"]
    assert len(records) == 1 and records[0]["target_path"] == "eingebaut.md", audit_log()
