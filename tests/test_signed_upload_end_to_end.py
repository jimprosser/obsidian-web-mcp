"""The whole signed-upload chain against a real server process, over HTTP.

A client authenticates with a bearer token, calls vault_request_upload_url over MCP, and
POSTs the bytes to the returned URL without a token. The server is the production entry
point (serve()) in its own process, so the MCP transport, the lifespan, build_app(), the
bearer middleware and uvicorn's access log are all the real ones.

The negative controls are in the same run: without the token the MCP call is refused,
and a tampered signature is refused, so a passing upload means the token and the
signature were actually checked.
"""

import hashlib
import json
import urllib.error
import urllib.request

import pytest

from ._live_server import call_tool_over_http, live_server

PDF = b"%PDF-1.4\n" + bytes(range(256)) * 400


@pytest.fixture
def vault(tmp_path):
    v = tmp_path / "vault"
    v.mkdir()
    (v / "note.md").write_text("# Note\n", encoding="utf-8")
    return v


def _post(url: str, body: bytes, content_type: str = "application/pdf", token: str | None = None):
    headers = {"Content-Type": content_type}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def test_client_requests_url_over_mcp_and_uploads_without_token(tmp_path, vault):
    env = {
        "VAULT_UPLOAD_STAGING_DIR": str(tmp_path / "staging"),
        "VAULT_UPLOAD_URL_SECRET": "e2e-upload-secret",
        "VAULT_AUDIT_LOG_PATH": str(tmp_path / "audit" / "audit.jsonl"),
    }
    with live_server(tmp_path, vault, env) as (base_url, log_path):
        # Negative control: the MCP endpoint really demands the token.
        status, _ = _post(f"{base_url}/", b"{}", content_type="application/json")
        assert status == 401, status

        grant = call_tool_over_http(
            base_url,
            "vault_request_upload_url",
            {"path": "ablage/vertrag.pdf", "media_type": "application/pdf", "max_size_bytes": len(PDF)},
        )
        assert "error" not in grant, grant
        assert grant["upload_url"].startswith(base_url + "/upload/"), grant

        # Negative control: the signature is really checked.
        tampered = grant["upload_url"].replace("signature=", "signature=0")
        status, body = _post(tampered, PDF)
        assert status in (403, 404), (status, body)
        assert not (vault / "ablage" / "vertrag.pdf").exists()

        status, body = _post(grant["upload_url"], PDF)
        assert status == 201, (status, body)
        assert (vault / "ablage" / "vertrag.pdf").read_bytes() == PDF

        replay_status, _ = _post(grant["upload_url"], PDF)
        assert replay_status == 409

    log = log_path.read_text(errors="replace")
    assert "POST /upload/" in log, "the access log line itself must be there"
    signature = grant["upload_url"].split("signature=")[1]
    assert signature not in log, "the signed URL reached the server log"

    records = [json.loads(line) for line in (tmp_path / "audit" / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    uploads = [r for r in records if r["operation"] == "vault_upload" and r["operation_status"] == "success"]
    assert len(uploads) == 1, records
    assert uploads[0]["target_path"] == "ablage/vertrag.pdf"
    assert uploads[0]["size_after"] == len(PDF)
    assert uploads[0]["checksum_after"] == hashlib.sha256(PDF).hexdigest()
