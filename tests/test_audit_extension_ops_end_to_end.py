"""Extension audit registration against a real server process, over HTTP.

serve() runs in its own process with an extension that registers two tools and declares
them from register_tools, the way an extension ships. A client with the bearer token
calls them over MCP streamable HTTP. The audit log is a real file the child writes.

The negative control runs in the same server: a third tool uses the same wrapper without
declaring its name, and its call must leave no record while the declared ones do.
"""

import json

from ._live_server import call_tool_over_http, live_server

BOOTSTRAP = '''
import json

from obsidian_vault_mcp.audit import register_audit_operation, run_audited
from obsidian_vault_mcp.extensions import Extension
from obsidian_vault_mcp.vault import resolve_vault_path, write_file_atomic


class AuditedExtension(Extension):
    def register_tools(self, mcp):
        register_audit_operation("e2e_write", kind="mutation")
        register_audit_operation("e2e_read", kind="read")

        @mcp.tool(name="e2e_write")
        def e2e_write(path: str, content: str) -> str:
            def work():
                is_new, size = write_file_atomic(path, content)
                return json.dumps({"path": path, "created": is_new, "size": size})
            return run_audited("e2e_write", work, path=path)

        @mcp.tool(name="e2e_read")
        def e2e_read(path: str) -> str:
            def work():
                return json.dumps({"path": path, "size": resolve_vault_path(path).stat().st_size})
            return run_audited("e2e_read", work, path=path)

        @mcp.tool(name="e2e_undeclared")
        def e2e_undeclared(path: str, content: str) -> str:
            def work():
                write_file_atomic(path, content)
                return json.dumps({"path": path})
            return run_audited("e2e_undeclared", work, path=path)


EXTENSIONS = [AuditedExtension()]
'''


def _records(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _run(tmp_path, include_reads: bool):
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "da.md").write_bytes(b"schon da\n")
    audit = tmp_path / "audit" / "audit.jsonl"
    env = {"VAULT_AUDIT_LOG_PATH": str(audit), "VAULT_AUDIT_LOG_INCLUDE_READS": "true" if include_reads else "false"}
    with live_server(tmp_path, vault, env, bootstrap=BOOTSTRAP) as (base_url, _log):
        write = call_tool_over_http(base_url, "e2e_write", {"path": "neu.md", "content": "inhalt\n"})
        read = call_tool_over_http(base_url, "e2e_read", {"path": "da.md"})
        undeclared = call_tool_over_http(base_url, "e2e_undeclared", {"path": "still.md", "content": "x\n"})
    assert "error" not in write and "error" not in read and "error" not in undeclared, (write, read, undeclared)
    assert (vault / "neu.md").exists() and (vault / "still.md").exists(), "negative control: the writes did not happen"
    return {r["operation"]: r for r in _records(audit)}, _records(audit)


def test_declared_tools_are_audited_over_http_and_the_undeclared_one_is_not(tmp_path):
    by_op, records = _run(tmp_path, include_reads=True)

    assert set(by_op) == {"e2e_write", "e2e_read"}, records
    assert by_op["e2e_write"]["target_path"] == "neu.md"
    assert by_op["e2e_write"]["size_before"] is None and by_op["e2e_write"]["size_after"] == len(b"inhalt\n")
    assert by_op["e2e_read"]["target_path"] == "da.md"
    assert by_op["e2e_read"]["token_id_hash"], "the record must carry the caller, as built-in records do"


def test_a_declared_read_stays_out_while_reads_are_excluded(tmp_path):
    by_op, records = _run(tmp_path, include_reads=False)

    assert set(by_op) == {"e2e_write"}, records
