"""Signed direct upload, tested through what serves it: build_app() and the registered tool.

Every client-facing test here requests the URL through the MCP tool registration and sends
the bytes through the app build_app() returns, bearer middleware included, with no
Authorization header. A hand-built Starlette app with its own handler is exactly the
substitute that let a NameError ship in the first version of this route.

The tests follow the review of that first version point by point, and each is written to
fail against it: the route must work at all, /upload must be reserved from VAULT_MCP_PATH
and from extension routes, the grant must be checked before any body byte is read, the
body must stream to disk under a hard cap, the commit must be audited and fire a write
event, the signed URL must not reach the access log, the stale sweep must only remove
upload dirs, and the path must do something vault_write_binary cannot.
"""

import asyncio
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.routing import Route
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth as auth_module
from obsidian_vault_mcp import config, extensions, server, write_events

PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 8
SECRET_TOKEN = "bearer-token-for-tests"


@pytest.fixture(autouse=True)
def upload_env(vault_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "UPLOAD_STAGING_DIR", tmp_path / "uploads")
    monkeypatch.setattr(config, "VAULT_UPLOAD_URL_SECRET", "upload-secret")
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", SECRET_TOKEN)
    audit_log = tmp_path / "audit" / "audit.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(audit_log))
    write_events._write_listeners.clear()
    yield audit_log
    write_events._write_listeners.clear()


def request_url(**arguments) -> dict:
    """The registered MCP tool, as a client calls it."""
    arguments.setdefault("media_type", "image/png")
    arguments.setdefault("max_size_bytes", len(PNG))
    result = asyncio.run(server.mcp.call_tool("vault_request_upload_url", arguments))
    if isinstance(result, tuple):
        result = result[0]
    payload = json.loads("".join(getattr(block, "text", "") for block in result))
    assert "error" not in payload, payload
    return payload


def local_path(upload_url: str) -> str:
    parsed = urlparse(upload_url)
    return f"{parsed.path}?{parsed.query}"


def client() -> TestClient:
    return TestClient(server.build_app(), raise_server_exceptions=False)


# --- The route works through build_app, without a bearer token -----------------------------

def test_upload_through_build_app_writes_the_file(vault_dir):
    grant = request_url(path="bilder/scan.png")

    response = client().post(local_path(grant["upload_url"]), content=PNG, headers={"Content-Type": "image/png"})

    assert response.status_code == 201, response.text
    assert (vault_dir / "bilder" / "scan.png").read_bytes() == PNG


def test_url_is_single_use(vault_dir):
    grant = request_url(path="scan.png", overwrite=True)
    c = client()
    first = c.post(local_path(grant["upload_url"]), content=PNG, headers={"Content-Type": "image/png"})

    second = c.post(local_path(grant["upload_url"]), content=b"\x89PNG other", headers={"Content-Type": "image/png"})

    assert first.status_code == 201, first.text
    assert second.status_code == 409, second.text
    assert (vault_dir / "scan.png").read_bytes() == PNG


def test_wrong_content_type_does_not_burn_the_url(vault_dir):
    grant = request_url(path="scan.png")
    c = client()

    wrong = c.post(local_path(grant["upload_url"]), content=PNG, headers={"Content-Type": "application/pdf"})
    right = c.post(local_path(grant["upload_url"]), content=PNG, headers={"Content-Type": "image/png"})

    assert wrong.status_code == 415, wrong.text
    assert right.status_code == 201, right.text


def test_checksum_mismatch_writes_nothing_and_leaves_no_temp_file(vault_dir):
    grant = request_url(path="scan.png", expected_sha256="0" * 64)

    response = client().post(local_path(grant["upload_url"]), content=PNG, headers={"Content-Type": "image/png"})

    assert response.status_code == 422, response.text
    assert not (vault_dir / "scan.png").exists()
    assert list(config.UPLOAD_STAGING_DIR.rglob("*.part")) == []


def test_multipart_is_refused(vault_dir):
    grant = request_url(path="scan.png")

    response = client().post(local_path(grant["upload_url"]), files={"file": ("scan.png", PNG, "image/png")})

    assert response.status_code == 415, response.text
    assert not (vault_dir / "scan.png").exists()


# --- /upload is reserved ----------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/upload", "/upload/mcp", "/upload/mcp/x"])
def test_mcp_path_under_upload_is_rejected(path):
    """With the exemption in place, mounting MCP here served the vault without a token."""
    with pytest.raises(ValueError, match="upload"):
        config._validate_mcp_path(path)


@pytest.mark.parametrize("route_path", ["/upload/{a}/{b}", "/upload/{upload_id}", "/upload"])
def test_extension_route_in_the_upload_namespace_is_rejected(route_path):
    class UploadSquatter(extensions.Extension):
        def register_routes(self, app):
            async def handler(request):
                return JSONResponse({"vault": "contents"})

            app.routes.insert(0, Route(route_path, handler, methods=["POST", "GET"]))

    with pytest.raises(ValueError, match="upload"):
        server.build_app([UploadSquatter()])


@pytest.mark.parametrize(
    "method,path",
    [("POST", "/upload/a/b"), ("POST", "/upload"), ("GET", "/upload/0f0e0d0c-0b0a-4908-8706-050403020100")],
)
def test_only_post_to_one_id_segment_is_bearer_exempt(method, path):
    response = client().request(method, path)

    assert response.status_code == 401, (method, path, response.status_code)


# --- The grant is checked before the body is read, and the body streams under a cap ---------

class _CountingReceive:
    """Hands the app a body in chunks and counts how many it pulls."""

    def __init__(self, total: int, chunk: int = 32 * 1024):
        self.chunks = [b"\x89" * chunk for _ in range(total // chunk)]
        self.pulled = 0

    async def __call__(self):
        if self.pulled < len(self.chunks):
            self.pulled += 1
            return {"type": "http.request", "body": self.chunks[self.pulled - 1], "more_body": self.pulled < len(self.chunks)}
        await asyncio.sleep(3600)


def _drive(app, path_and_query: str, receive, headers=()):
    path, _, query = path_and_query.partition("?")
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
        "scheme": "http", "server": ("testserver", 80), "client": ("127.0.0.1", 1),
        "root_path": "", "path": path, "raw_path": path.encode(), "query_string": query.encode(),
        "headers": [(b"host", b"testserver"), (b"content-type", b"image/png"), *headers],
    }
    sent = []

    async def send(message):
        sent.append(message)

    async def run():
        await asyncio.wait_for(app(scope, receive, send), timeout=30)

    asyncio.run(run())
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    return status


def test_bad_signature_is_refused_without_pulling_the_body():
    grant = request_url(path="scan.png")
    bad = local_path(grant["upload_url"]).replace("signature=", "signature=0")
    receive = _CountingReceive(2 * 1024 * 1024)

    status = _drive(server.build_app(), bad, receive)

    assert status in (403, 404), status
    assert receive.pulled == 0, f"pulled {receive.pulled} body chunks before refusing"


def test_body_without_content_length_stops_at_the_cap(vault_dir):
    grant = request_url(path="scan.png", max_size_bytes=1024)
    receive = _CountingReceive(64 * 32 * 1024)

    status = _drive(server.build_app(), local_path(grant["upload_url"]), receive)

    assert status == 413, status
    assert receive.pulled == 1, f"pulled {receive.pulled} of 64 chunks past a 1 KB cap"
    assert not (vault_dir / "scan.png").exists()
    assert list(config.UPLOAD_STAGING_DIR.rglob("*.part")) == []


def test_route_never_buffers_the_whole_body(vault_dir, monkeypatch):
    from starlette.requests import Request

    async def forbidden(self):
        raise AssertionError("the upload route read the whole body into memory")

    monkeypatch.setattr(Request, "body", forbidden)
    grant = request_url(path="scan.png")

    response = client().post(local_path(grant["upload_url"]), content=PNG, headers={"Content-Type": "image/png"})

    assert response.status_code == 201, response.text


def test_uploads_what_vault_write_binary_cannot(vault_dir, monkeypatch):
    """The reason the route exists: a file above the base64 tool's limit."""
    import base64

    monkeypatch.setattr(config, "VAULT_UPLOAD_MAX_BYTES", 32_000_000, raising=False)
    big = b"%PDF-1.7\n" + os.urandom(config.MAX_BINARY_SIZE + 1_000_000)

    # Negative control: the base64 tool refuses this file.
    try:
        result = asyncio.run(server.mcp.call_tool(
            "vault_write_binary",
            {"path": "gross-b64.pdf", "data": base64.b64encode(big).decode("ascii"), "media_type": "application/pdf"},
        ))
        refusal = json.dumps([getattr(block, "text", "") for block in (result[0] if isinstance(result, tuple) else result)])
    except Exception as exc:  # input validation raises inside FastMCP
        refusal = str(exc)
    assert "error" in refusal.lower() or "too long" in refusal.lower() or "at most" in refusal.lower(), refusal[:300]
    assert not (vault_dir / "gross-b64.pdf").exists()

    grant = request_url(path="gross.pdf", media_type="application/pdf", max_size_bytes=len(big))

    response = client().post(local_path(grant["upload_url"]), content=big, headers={"Content-Type": "application/pdf"})

    assert response.status_code == 201, response.text
    assert (vault_dir / "gross.pdf").stat().st_size == len(big) > config.MAX_BINARY_SIZE


# --- The commit is audited and fires a write event ------------------------------------------

def test_commit_is_audited_and_fires_a_write_event(vault_dir, upload_env):
    events = []
    write_events.register_write_listener(lambda op, paths: events.append((op, paths)))
    grant = request_url(path="scan.png")

    client().post(local_path(grant["upload_url"]), content=PNG, headers={"Content-Type": "image/png"})

    records = [json.loads(line) for line in upload_env.read_text(encoding="utf-8").splitlines()]
    uploads = [r for r in records if r["target_path"] == "scan.png" and r["operation_status"] == "success"]
    assert uploads and uploads[-1]["size_after"] == len(PNG), records
    assert ("created", ["scan.png"]) in events


def test_refused_grant_is_not_audited(upload_env):
    """Unauthenticated noise must not grow the audit log."""
    client().post("/upload/0f0e0d0c-0b0a-4908-8706-050403020100?expires=1&signature=x", content=PNG,
                  headers={"Content-Type": "image/png"})

    assert not upload_env.exists() or upload_env.read_text(encoding="utf-8") == ""


# --- The stale sweep only removes upload dirs ------------------------------------------------

def test_stale_sweep_removes_old_upload_dirs_and_nothing_else(tmp_path):
    root = config.UPLOAD_STAGING_DIR
    root.mkdir(parents=True)
    old = time.time() - 3 * 24 * 3600
    stale_upload = root / "0f0e0d0c-0b0a-4908-8706-050403020100"
    foreign = root / "operator-data"
    for directory in (stale_upload, foreign):
        directory.mkdir()
        (directory / "keep.txt").write_text("x")
        os.utime(directory, (old, old))

    request_url(path="scan.png")  # requesting a URL runs the sweep

    assert not stale_upload.exists(), "negative control: the sweep did not run"
    assert (foreign / "keep.txt").exists(), "the sweep removed a directory that is not an upload"


# --- The signed URL stays out of the access log ----------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve_once_and_capture(log_config, capfd) -> str:
    import uvicorn

    port = _free_port()
    config_ = uvicorn.Config(server.build_app(), host="127.0.0.1", port=port, lifespan="off", log_config=log_config)
    uv = uvicorn.Server(config_)
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not uv.started and time.time() < deadline:
        time.sleep(0.05)
    assert uv.started, "uvicorn did not start"
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/upload/0f0e0d0c-0b0a-4908-8706-050403020100?expires=1&signature=SIGNATURE-VALUE-123",
            data=PNG, method="POST", headers={"Content-Type": "image/png"},
        )
        try:
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError:
            pass
        time.sleep(0.3)
    finally:
        uv.should_exit = True
        thread.join(timeout=10)
    out, err = capfd.readouterr()
    return out + err


def test_access_log_does_not_record_the_signature(capfd):
    from uvicorn.config import LOGGING_CONFIG

    stock = _serve_once_and_capture(LOGGING_CONFIG, capfd)
    assert "SIGNATURE-VALUE-123" in stock, f"negative control: stock access log did not show the URL: {stock!r}"

    served = _serve_once_and_capture(getattr(server, "uvicorn_log_config", lambda: LOGGING_CONFIG)(), capfd)

    assert "POST /upload/" in served, f"the access line itself must survive: {served!r}"
    assert "SIGNATURE-VALUE-123" not in served


def test_serve_uses_the_redacting_log_config(vault_dir, monkeypatch):
    import uvicorn

    captured = {}
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: captured.update(k))
    monkeypatch.setattr(server, "VAULT_PATH", vault_dir)
    monkeypatch.setattr(server.frontmatter_index, "start", lambda: None)
    monkeypatch.setattr(server.frontmatter_index, "stop", lambda: None)
    monkeypatch.setattr(server.atexit, "register", lambda fn, *a, **k: None)

    server.serve()

    filters = captured.get("log_config", {}).get("handlers", {}).get("access", {}).get("filters", [])
    assert "redact_upload_signature" in filters, captured.get("log_config")
