"""Per-client read/write access against the real serve() in its own process.

A client registers, signs in and gets its own token over HTTP, as a connector does.
vault-mcp-oauth, run as its own process against the same state, sets the client's access
while the server runs, and the next tool call over MCP shows the effect: no restart, no
stub between the token and the tool.

The server carries an extension so the fail-closed rule is tested where it matters: an
operation the audit log does not know is refused to a read-only client, and one it
declared as a read is not, whether or not the tool goes through run_audited.
"""

import json
import subprocess
import sys

import pytest

from ._live_server import TOKEN, call_tool_over_http, child_env, live_server
from .test_oauth_end_to_end import _v1_token_over_http

BOOTSTRAP = '''
import json

from obsidian_vault_mcp.audit import register_audit_operation, run_audited
from obsidian_vault_mcp.extensions import Extension
from obsidian_vault_mcp.vault import resolve_vault_path, write_file_atomic


class AccessExtension(Extension):
    def register_tools(self, mcp):
        register_audit_operation("e2e_read", kind="read")
        register_audit_operation("e2e_bypass_read", kind="read")

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

        # These two never call run_audited: only the check at tool dispatch can stop them.
        @mcp.tool(name="e2e_bypass_write")
        def e2e_bypass_write(path: str, content: str) -> str:
            write_file_atomic(path, content)
            return json.dumps({"path": path})

        # Structured output: its schema cannot carry the {"error": ...} text a refusal is.
        @mcp.tool(name="e2e_structured_write")
        def e2e_structured_write(path: str, content: str) -> dict[str, str]:
            write_file_atomic(path, content)
            return {"path": path}

        @mcp.tool(name="e2e_bypass_read")
        def e2e_bypass_read(path: str) -> str:
            return json.dumps({"path": path, "size": resolve_vault_path(path).stat().st_size})


EXTENSIONS = [AccessExtension()]
'''


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """One running server for the module; every test registers a client of its own."""
    tmp_path = tmp_path_factory.mktemp("access")
    vault = tmp_path / "vault"
    vault.mkdir()
    env = {
        "OAUTH_CLIENTS_PATH": str(tmp_path / "state" / "oauth_clients.json"),
        "VAULT_OAUTH_PASSWORD": "hunter2",
        "VAULT_AUDIT_LOG_PATH": str(tmp_path / "audit" / "audit.jsonl"),
        "VAULT_UPLOAD_URL_SECRET": "access-upload-secret",
        "VAULT_UPLOAD_STAGING_DIR": str(tmp_path / "uploads"),
    }
    with live_server(tmp_path, vault, env, bootstrap=BOOTSTRAP) as (base_url, _log):
        yield {"base_url": base_url, "vault": vault, "tmp_path": tmp_path, "env": env}


def _set_access(server, client_id, level):
    """vault-mcp-oauth clients access, as its own process, while the server runs."""
    done = subprocess.run(
        [sys.executable, "-c",
         "from obsidian_vault_mcp.oauth_admin import main; raise SystemExit(main())",
         "clients", "access", client_id, level],
        env=child_env(server["tmp_path"] / "home", server["vault"], 0, server["env"]),
        capture_output=True, text=True, timeout=60,
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == {"client_id": client_id, "access": level}


def _read_only_client(server):
    """A client that signed in over HTTP, then was set to read."""
    client_id, token = _v1_token_over_http(server["base_url"])
    _set_access(server, client_id, "read")
    return client_id, token


def _call(server, name, arguments, token=TOKEN):
    """Call a tool over MCP with a client's token; by default the master token."""
    return call_tool_over_http(server["base_url"], name, arguments, token=token)


def _refused(answer):
    """Whether a tool answered with the read-only refusal."""
    return "read-only" in answer.get("error", "")


def test_read_only_client_can_read(server):
    (server["vault"] / "readable.md").write_text("# Readable\n")
    _client_id, token = _read_only_client(server)

    answer = _call(server, "vault_read", {"path": "readable.md"}, token)

    assert "error" not in answer, answer
    assert answer["content"] == "# Readable\n"


def test_read_only_client_is_refused_a_write_and_the_file_is_unchanged(server):
    note = server["vault"] / "kept.md"
    note.write_text("# Original\n")
    client_id, token = _read_only_client(server)

    answer = _call(server, "vault_write", {"path": "kept.md", "content": "# Replaced\n"}, token)

    assert _refused(answer), answer
    assert note.read_text() == "# Original\n"
    # The refusal is recorded through the record's own outcome fields.
    audit = server["tmp_path"] / "audit" / "audit.jsonl"
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    (refusal,) = [r for r in records if r["client_id"] == client_id]
    assert refusal["operation"] == "vault_write"
    assert refusal["operation_status"] == "error"
    assert "read-only" in refusal["error"]
    assert refusal["checksum_after"] is None


def test_read_only_client_is_refused_an_operation_not_declared_as_a_read(server):
    (server["vault"] / "declared.md").write_text("x\n")
    _client_id, token = _read_only_client(server)

    undeclared = _call(server, "e2e_undeclared", {"path": "undeclared.md", "content": "x\n"}, token)
    declared_read = _call(server, "e2e_read", {"path": "declared.md"}, token)

    assert _refused(undeclared), undeclared
    assert not (server["vault"] / "undeclared.md").exists()
    assert declared_read == {"path": "declared.md", "size": 2}


def test_read_only_client_is_refused_an_undeclared_tool_that_skips_run_audited(server):
    note = server["vault"] / "bypassed.md"
    note.write_text("# Original\n")
    _client_id, token = _read_only_client(server)

    undeclared = _call(server, "e2e_bypass_write", {"path": "bypassed.md", "content": "x\n"}, token)
    declared_read = _call(server, "e2e_bypass_read", {"path": "bypassed.md"}, token)

    assert _refused(undeclared), undeclared
    assert note.read_text() == "# Original\n"
    assert declared_read == {"path": "bypassed.md", "size": len("# Original\n")}


def test_refusal_of_a_structured_output_tool_still_names_the_reason(server):
    note = server["vault"] / "structured.md"
    note.write_text("# Original\n")
    _client_id, token = _read_only_client(server)

    answer = _call(server, "e2e_structured_write", {"path": "structured.md", "content": "x\n"}, token)

    assert answer.get("isError") is True, answer
    assert answer["error"].startswith("This client is read-only"), answer
    assert note.read_text() == "# Original\n"


def test_read_only_client_keeps_the_built_in_reads_that_skip_run_audited(server):
    _client_id, token = _read_only_client(server)

    path = _call(server, "vault_daily_note_path", {}, token)
    summary = _call(server, "vault_analytics_summary", {}, token)
    findings = _call(server, "vault_analytics_findings", {"category": "frontmatter_missing"}, token)

    assert "error" not in path and path["path"].endswith(".md"), path
    assert "error" not in summary and "examples" in summary, summary
    assert "error" not in findings and findings["category"] == "frontmatter_missing", findings


def test_read_only_client_is_refused_dry_runs_of_edit_and_move(server):
    (server["vault"] / "dry.md").write_text("# Dry\n")
    _client_id, token = _read_only_client(server)

    edit = _call(server, "vault_edit", {
        "path": "dry.md", "edits": [{"old_text": "# Dry", "new_text": "# Wet"}], "dry_run": True,
    }, token)
    move = _call(server, "vault_move", {
        "source": "dry.md", "destination": "moved.md", "dry_run": True,
    }, token)

    # The refusal is the whole answer: no preview of the edit or of the link rewrites.
    assert _refused(edit) and set(edit) == {"error"}, edit
    assert _refused(move) and set(move) == {"error"}, move


def test_access_change_applies_to_the_next_request_without_a_restart(server):
    note = server["vault"] / "switched.md"
    client_id, token = _v1_token_over_http(server["base_url"])

    first = _call(server, "vault_write", {"path": "switched.md", "content": "one\n"}, token)
    _set_access(server, client_id, "read")
    second = _call(server, "vault_write", {"path": "switched.md", "content": "two\n"}, token)
    after_read_only = note.read_text()
    _set_access(server, client_id, "write")
    third = _call(server, "vault_write", {"path": "switched.md", "content": "three\n"}, token)

    assert "error" not in first, first
    assert _refused(second), second
    assert after_read_only == "one\n"
    assert "error" not in third, third
    assert note.read_text() == "three\n"


def test_master_token_writes_while_a_client_is_read_only(server):
    _read_only_client(server)

    answer = _call(server, "vault_write", {"path": "master.md", "content": "# Master\n"})

    assert "error" not in answer, answer
    assert (server["vault"] / "master.md").read_text() == "# Master\n"


def test_read_only_client_is_not_handed_an_upload_url(server):
    _client_id, token = _read_only_client(server)
    arguments = {"path": "upload.png", "media_type": "image/png", "max_size_bytes": 1024}

    refused = _call(server, "vault_request_upload_url", arguments, token)
    grants_after_refusal = list((server["tmp_path"] / "uploads").glob("*/metadata.json"))
    granted = _call(server, "vault_request_upload_url", arguments)

    assert _refused(refused), refused
    assert "upload_url" not in refused
    assert grants_after_refusal == []
    assert granted["upload_url"].startswith(server["base_url"] + "/upload/"), granted
