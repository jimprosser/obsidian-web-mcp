"""Signed direct download, tested through what serves it: build_app() and the registered tool.

Every client-facing test requests the URL through the MCP tool registration and fetches the
bytes through the app build_app() returns, bearer middleware included, with no
Authorization header. The cases come from what reaches the route from outside (method,
path shape, query string, each signed field) and from the file changing between the
moment the URL is issued and the moment it is fetched.
"""

import asyncio
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlparse

import pytest
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth as auth_module
from obsidian_vault_mcp import config, extensions, server
from obsidian_vault_mcp.tools import download as download_mod

PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 8
SECRET_TOKEN = "bearer-token-for-tests"
UNKNOWN_ID = "0f0e0d0c-0b0a-4908-8706-050403020100"


@pytest.fixture(autouse=True)
def download_env(vault_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VAULT_DOWNLOAD_URL_SECRET", "download-secret")
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", SECRET_TOKEN)
    (vault_dir / "bilder").mkdir()
    (vault_dir / "bilder" / "scan.png").write_bytes(PNG)
    audit_log = tmp_path / "audit" / "audit.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(audit_log))
    yield audit_log


def call_tool(**arguments) -> dict:
    """The registered MCP tool, as a client calls it."""
    result = asyncio.run(server.mcp.call_tool("vault_request_download_url", arguments))
    if isinstance(result, tuple):
        result = result[0]
    return json.loads("".join(getattr(block, "text", "") for block in result))


def request_url(path="bilder/scan.png", **arguments) -> dict:
    payload = call_tool(path=path, **arguments)
    assert "error" not in payload, payload
    return payload


def local_path(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.path}?{parsed.query}"


def with_query(grant: dict, **replace) -> str:
    parsed = urlparse(grant["download_url"])
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params.update(replace)
    return parsed.path + "?" + urlencode(params)


def client() -> TestClient:
    return TestClient(server.build_app(), raise_server_exceptions=False)


# --- The route works through build_app, without a bearer token -----------------------------

def test_download_through_build_app_serves_the_exact_bytes():
    grant = request_url()

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 200, response.text
    assert response.content == PNG
    assert grant["size"] == len(PNG)
    assert response.headers["content-type"] == "image/png"
    assert response.headers["content-length"] == str(len(PNG))


def test_the_url_can_be_fetched_again_until_it_expires():
    """Stateless by design (review of #115): the short lifetime bounds a leaked URL."""
    grant = request_url()
    c = client()

    first = c.get(local_path(grant["download_url"]))
    second = c.get(local_path(grant["download_url"]))

    assert first.status_code == second.status_code == 200
    assert first.content == second.content == PNG


def test_a_file_larger_than_one_chunk_streams_whole(vault_dir):
    big = os.urandom(3 * 1024 * 1024 + 17)
    (vault_dir / "big.bin").write_bytes(big)
    grant = request_url("big.bin")

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 200
    assert response.content == big


@pytest.mark.parametrize("name,content", [("seite.html", b"<script>alert(1)</script>"), ("bild.svg", b"<svg onload=alert(1)/>")])
def test_active_content_is_an_attachment_never_rendered(vault_dir, name, content):
    """Served inline from this origin, a vault's HTML or SVG would run next to the OAuth login."""
    (vault_dir / name).write_bytes(content)
    grant = request_url(name)

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in response.headers["content-security-policy"]
    assert "default-src 'none'" in response.headers["content-security-policy"]


def test_the_response_is_not_cached():
    grant = request_url()

    response = client().get(local_path(grant["download_url"]))

    assert response.headers["cache-control"] == "no-store"


def test_a_non_ascii_filename_is_carried_without_breaking_the_header(vault_dir):
    (vault_dir / 'Prüfung "final".pdf').write_bytes(b"%PDF-1.4\n")
    grant = request_url('Prüfung "final".pdf')

    response = client().get(local_path(grant["download_url"]))

    disposition = response.headers["content-disposition"]
    assert response.status_code == 200
    assert "filename*=UTF-8''Pr%C3%BCfung%20%22final%22.pdf" in disposition
    assert 'filename="Pr_fung _final_.pdf"' in disposition


def test_a_path_with_a_newline_is_signed_unambiguously(vault_dir):
    (vault_dir / "a\nb.txt").write_bytes(b"newline in the name")
    grant = request_url("a\nb.txt")

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 200 and response.content == b"newline in the name"


# --- What the tool refuses -----------------------------------------------------------------

@pytest.mark.parametrize("path", ["../outside.txt", ".obsidian/config.json", "missing.png", "bilder", "a\x00b"])
def test_the_tool_refuses_what_vault_read_refuses(path):
    payload = call_tool(path=path)

    assert "error" in payload, payload
    assert "download_url" not in payload


def test_the_tool_refuses_a_symlink_that_leaves_the_vault(vault_dir, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("outside the vault", encoding="utf-8")
    (vault_dir / "link.txt").symlink_to(outside)

    payload = call_tool(path="link.txt")

    assert "error" in payload and "download_url" not in payload, payload


def test_the_tool_refuses_a_hardlinked_file(vault_dir, tmp_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("outside the vault", encoding="utf-8")
    os.link(outside, vault_dir / "hard.txt")

    payload = call_tool(path="hard.txt")

    assert "error" in payload and "download_url" not in payload, payload


def test_the_lifetime_is_clamped_to_the_maximum(monkeypatch):
    monkeypatch.setattr(config, "VAULT_DOWNLOAD_URL_MAX_TTL_SECONDS", 60)

    grant = request_url(ttl_seconds=86400)

    assert grant["expires_in_seconds"] == 60
    assert grant["expires_at"] - time.time() <= 61


# --- The race the guard cannot see: the path changes after it was resolved -----------------
#
# The guard resolves the path, then the file is opened. Whatever sits at the resolved path
# by the time of the open is what fstat describes. These tests put the swap exactly there,
# by handing the open a path the guard would have refused.

def _guard_resolves_to(monkeypatch, target):
    monkeypatch.setattr(download_mod, "resolve_vault_read_path", lambda _path: target)


def test_a_symlink_swapped_in_after_the_guard_is_not_followed(vault_dir, tmp_path, monkeypatch):
    outside = tmp_path / "secret.txt"
    outside.write_text("outside the vault", encoding="utf-8")
    swapped = vault_dir / "swapped.txt"
    swapped.symlink_to(outside)
    _guard_resolves_to(monkeypatch, swapped)

    payload = call_tool(path="swapped.txt")

    assert "error" in payload and "download_url" not in payload, payload


def test_a_hardlink_swapped_in_after_the_guard_is_refused_from_fstat(vault_dir, tmp_path, monkeypatch):
    outside = tmp_path / "secret.txt"
    outside.write_text("outside the vault", encoding="utf-8")
    hard = vault_dir / "hard.txt"
    os.link(outside, hard)
    _guard_resolves_to(monkeypatch, hard)

    payload = call_tool(path="hard.txt")

    assert "error" in payload and "download_url" not in payload, payload


def test_a_hardlink_made_after_issue_is_refused_from_fstat_at_the_route(vault_dir, tmp_path, monkeypatch):
    """Same inode, size and mtime: only the link count tells, and only fstat sees it here."""
    grant = request_url()
    target = vault_dir / "bilder" / "scan.png"
    os.link(target, tmp_path / "second-name.png")
    _guard_resolves_to(monkeypatch, target)

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 409, response.text


def test_a_directory_swapped_in_after_the_guard_is_refused(vault_dir, monkeypatch):
    _guard_resolves_to(monkeypatch, vault_dir / "bilder")

    payload = call_tool(path="bilder/scan.png")

    assert "error" in payload and "download_url" not in payload, payload


@pytest.mark.skipif(not os.path.exists("/dev/null"), reason="needs a character device with one link")
def test_a_device_swapped_in_after_the_guard_is_refused(monkeypatch):
    """One link and not a directory, so only the regular-file check stands in the way."""
    _guard_resolves_to(monkeypatch, "/dev/null")

    payload = call_tool(path="bilder/scan.png")

    assert "error" in payload and "download_url" not in payload, payload


# --- Each signed field, the signature, and the expiry -----------------------------------------

@pytest.mark.parametrize(
    "replace",
    [
        {"path": "test-note.md"},
        {"device": "1"},
        {"inode": "1"},
        {"size": "1"},
        {"mtime_ns": "1"},
        {"expires": str(int(time.time()) + 86400)},
        {"signature": "0" * 64},
        {"signature": "%C3%A9"},
        {"signature": "é"},
        {"signature": ""},
    ],
)
def test_a_changed_field_or_a_bad_signature_is_403(replace):
    grant = request_url()

    response = client().get(with_query(grant, **replace))

    assert response.status_code == 403, response.text
    assert response.content != PNG


def test_the_id_is_signed_too():
    grant = request_url()
    other_id = with_query(grant).replace(grant["download_id"], UNKNOWN_ID)

    response = client().get(other_id)

    assert response.status_code == 403, response.text


@pytest.mark.parametrize("drop", ["path", "device", "inode", "size", "mtime_ns", "expires"])
def test_a_missing_field_is_400(drop):
    grant = request_url()
    parsed = urlparse(grant["download_url"])
    params = {k: v for k, v in parse_qsl(parsed.query) if k != drop}

    response = client().get(parsed.path + "?" + urlencode(params))

    assert response.status_code == 400, response.text


@pytest.mark.parametrize("field", ["device", "inode", "size", "mtime_ns", "expires"])
def test_a_non_integer_field_is_400(field):
    grant = request_url()

    response = client().get(with_query(grant, **{field: "soon"}))

    assert response.status_code == 400, response.text


def test_an_encoded_signature_key_is_still_the_signature():
    """Starlette decodes query keys; %73ignature is signature, so it must still be checked."""
    grant = request_url()
    parsed = urlparse(grant["download_url"])

    response = client().get(parsed.path + "?" + parsed.query.replace("signature=", "%73ignature="))

    assert response.status_code == 200 and response.content == PNG


def test_an_expired_url_is_refused(monkeypatch):
    grant = request_url(ttl_seconds=1)
    later = time.time() + 3600
    monkeypatch.setattr(download_mod, "time", type("Clock", (), {"time": staticmethod(lambda: later)}))

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 410, response.text


@pytest.mark.parametrize("download_id", ["abc", "A" * 64, UNKNOWN_ID.upper()])
def test_a_malformed_id_is_404(download_id):
    response = client().get(f"/download/{download_id}?expires=1&signature=x")

    assert response.status_code == 404, response.text


# --- Only GET on one id segment is bearer-exempt -----------------------------------------------

@pytest.mark.parametrize(
    "method,path",
    [
        ("HEAD", f"/download/{UNKNOWN_ID}"),
        ("POST", f"/download/{UNKNOWN_ID}"),
        ("PUT", f"/download/{UNKNOWN_ID}"),
        ("DELETE", f"/download/{UNKNOWN_ID}"),
        ("OPTIONS", f"/download/{UNKNOWN_ID}"),
        ("GET", "/download"),
        ("GET", "/download/"),
        ("GET", f"/download/{UNKNOWN_ID}/"),
        ("GET", f"/download/{UNKNOWN_ID}/x"),
        ("GET", "/download/a_b"),
        ("GET", "/download/%2E%2E/health"),
        ("GET", f"http://testserver//download/{UNKNOWN_ID}"),
    ],
)
def test_only_get_on_one_id_segment_is_bearer_exempt(method, path):
    response = client().request(method, path)

    assert response.status_code == 401, (method, path, response.status_code)


def test_a_head_with_a_bearer_token_is_refused():
    grant = request_url()

    head = client().head(local_path(grant["download_url"]), headers={"Authorization": f"Bearer {SECRET_TOKEN}"})

    assert head.status_code == 405


# --- The file changes between issue and fetch -------------------------------------------------

def test_a_file_changed_in_place_is_not_served(vault_dir):
    grant = request_url()
    target = vault_dir / "bilder" / "scan.png"
    target.write_bytes(PNG[::-1])
    os.utime(target, ns=(time.time_ns(), time.time_ns() + 10_000_000))

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 409, response.text
    assert response.content != PNG[::-1]


def test_a_replacement_with_the_same_size_and_mtime_is_not_served(vault_dir):
    """Only the inode differs: the identity in the URL is the one thing that catches this."""
    grant = request_url()
    target = vault_dir / "bilder" / "scan.png"
    original = target.stat()
    replacement = vault_dir / "bilder" / "neu.png"
    replacement.write_bytes(b"Y" * len(PNG))
    os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
    os.replace(replacement, target)
    assert target.stat().st_size == original.st_size and target.stat().st_mtime_ns == original.st_mtime_ns

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 409, response.text
    assert b"Y" * 64 not in response.content


def test_a_deleted_file_is_404(vault_dir):
    grant = request_url()
    (vault_dir / "bilder" / "scan.png").unlink()

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 404


def test_a_file_swapped_for_a_symlink_out_of_the_vault_is_not_served(vault_dir, tmp_path):
    grant = request_url()
    outside = tmp_path / "secret.bin"
    outside.write_bytes(b"outside the vault")
    target = vault_dir / "bilder" / "scan.png"
    target.unlink()
    target.symlink_to(outside)

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code in (404, 409), response.text
    assert b"outside the vault" not in response.content


def test_a_parent_swapped_for_a_symlink_is_not_served(vault_dir, tmp_path):
    grant = request_url()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "scan.png").write_bytes(b"X" * len(PNG))
    (vault_dir / "bilder").rename(vault_dir / "bilder-alt")
    (vault_dir / "bilder").symlink_to(elsewhere)

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code in (404, 409), response.text
    assert b"X" * 64 not in response.content


def test_a_write_into_the_open_file_is_served_as_written(vault_dir, monkeypatch):
    """The documented limit: an open handle does not freeze the contents."""
    grant = request_url()
    target = vault_dir / "bilder" / "scan.png"
    real_open = download_mod._open_vault_file

    def open_then_write(path):
        fd, st = real_open(path)
        with open(target, "r+b") as f:
            f.write(b"Z" * 16)
        return fd, st

    monkeypatch.setattr(download_mod, "_open_vault_file", open_then_write)

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 200
    assert response.content == b"Z" * 16 + PNG[16:]


def test_a_file_that_grows_after_the_open_is_served_at_its_checked_size(vault_dir, monkeypatch):
    grant = request_url()
    target = vault_dir / "bilder" / "scan.png"
    real_open = download_mod._open_vault_file

    def open_then_append(path):
        fd, st = real_open(path)
        with open(target, "ab") as f:
            f.write(b"appended" * 1000)
        return fd, st

    monkeypatch.setattr(download_mod, "_open_vault_file", open_then_append)

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 200
    assert response.content == PNG
    assert response.headers["content-length"] == str(len(PNG))


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="needs /proc to count open descriptors")
def test_the_file_handle_is_closed_after_serving_and_after_a_refusal(vault_dir):
    c = client()
    target = vault_dir / "bilder" / "scan.png"
    before = len(os.listdir("/proc/self/fd"))

    for i in range(5):
        grant = request_url()
        assert c.get(local_path(grant["download_url"])).status_code == 200
        # Refused after the file was opened: the identity no longer matches.
        os.utime(target, ns=(time.time_ns(), time.time_ns() + (i + 1) * 10_000_000))
        assert c.get(local_path(grant["download_url"])).status_code == 409

    assert len(os.listdir("/proc/self/fd")) <= before


# --- /download is reserved, and the signed routes come first -----------------------------------

@pytest.mark.parametrize("path", ["/download", "/download/mcp", "/download/mcp/x"])
def test_mcp_path_under_download_is_rejected(path):
    with pytest.raises(ValueError, match="download"):
        config._validate_mcp_path(path)


@pytest.mark.parametrize(
    "route_path",
    ["/download/{a}/{b}", "/download/{download_id}", "/download", "/download/export", "/download/{n:int}", "/download/x/y", "/download/"],
)
def test_extension_route_in_the_download_namespace_is_rejected(route_path):
    class DownloadSquatter(extensions.Extension):
        def register_routes(self, app):
            async def handler(request):
                return JSONResponse({"vault": "contents"})

            app.routes.insert(0, Route(route_path, handler, methods=["GET", "POST"]))

    with pytest.raises(ValueError, match="download"):
        server.build_app([DownloadSquatter()])


@pytest.mark.parametrize(
    "method,path,signed_answer",
    [
        ("GET", "/download/export", "Unknown download id"),
        ("POST", "/upload/export", "Unknown upload id"),
    ],
)
def test_a_parameterized_extension_route_cannot_answer_a_tokenless_path(method, path, signed_answer):
    """Review of #115: Route("/{area}/export") passes the namespace check and, placed ahead
    of the signed routes, answered GET /download/export and POST /upload/export with no
    token and no signature. The signed routes now come first."""

    class AreaExport(extensions.Extension):
        def register_routes(self, app):
            async def handler(request):
                return JSONResponse({"vault": "contents"})

            app.routes.insert(0, Route("/{area}/export", handler, methods=["GET", "POST"]))

    app_client = TestClient(server.build_app([AreaExport()]), raise_server_exceptions=False)
    response = app_client.request(method, path)
    with_token = app_client.get("/notes/export", headers={"Authorization": f"Bearer {SECRET_TOKEN}"})

    assert response.status_code == 404, response.text
    assert signed_answer in response.text
    assert "contents" not in response.text
    assert with_token.status_code == 200 and "contents" in with_token.text, "negative control: the route is live"


# --- Audit ----------------------------------------------------------------------------------------

def _records(audit_log):
    if not audit_log.exists():
        return []
    return [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_issue_and_download_are_audited_as_reads_when_reads_are_audited(download_env, monkeypatch):
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", True)
    grant = request_url()
    client().get(local_path(grant["download_url"]))
    client().get(with_query(grant, signature="0" * 64))  # refused: not audited

    ops = [(r["operation"], r["target_path"], r["operation_status"], r["size_before"], r["checksum_before"])
           for r in _records(download_env)]

    assert ops == [
        ("vault_request_download_url", "bilder/scan.png", "success", len(PNG), None),
        ("vault_download", "bilder/scan.png", "success", len(PNG), None),
    ], ops


def test_issuing_a_url_with_read_auditing_on_never_hashes_the_file(download_env, monkeypatch):
    """Review of #115: run_audited snapshots a read's target with a checksum of the whole
    file, which would bring back the hash the stateless grant took out."""
    from obsidian_vault_mcp import audit

    snapshots = []
    real_snapshot = audit.snapshot_path
    monkeypatch.setattr(audit, "snapshot_path", lambda p: snapshots.append(p) or real_snapshot(p))
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", True)

    request_url()
    call_tool(path="missing.png")

    assert snapshots == []
    records = _records(download_env)
    assert [(r["operation_status"], r["checksum_before"]) for r in records] == [("success", None), ("error", None)]
    assert "missing.png" in (records[1]["error"] or "")


# --- the curl line is safe to run as given ----------------------------------------------------

@pytest.mark.skipif(not os.path.exists("/bin/sh"), reason="needs a POSIX shell")
@pytest.mark.parametrize("name", ["$(touch PWNED).txt", "`touch PWNED`.txt", "it's \"quoted\" $HOME.txt", "a\nb.txt"])
def test_the_curl_line_runs_no_command_from_the_file_name(vault_dir, tmp_path, name):
    """Review of #115: a note named $(id).txt ran id on whoever ran the curl line. Obsidian
    allows $, parentheses and backticks in names, and an agent runs the line as given."""
    import subprocess

    (vault_dir / name).write_bytes(b"x")
    grant = request_url(name)
    workdir = tmp_path / "client"
    workdir.mkdir()

    # A real shell runs the line; curl is a function that prints its arguments, one per NUL.
    shown = subprocess.run(
        ["/bin/sh", "-c", 'curl() { printf "%s\\0" "$@"; }; ' + grant["curl"]],
        cwd=workdir, capture_output=True, check=True,
    ).stdout.decode("utf-8").split("\0")[:-1]

    assert shown == ["-fsS", "-o", name, grant["download_url"]], shown
    assert list(workdir.iterdir()) == [], "a command from the file name ran"


def test_nothing_is_audited_when_reads_are_not(download_env, monkeypatch):
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", False)
    grant = request_url()
    client().get(local_path(grant["download_url"]))

    assert _records(download_env) == []


# --- The signed URL stays out of the access log ---------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve_once_and_capture(log_config, capfd, target: str = f"/download/{UNKNOWN_ID}") -> str:
    import uvicorn

    port = _free_port()
    uv = uvicorn.Server(uvicorn.Config(server.build_app(), host="127.0.0.1", port=port, lifespan="off", log_config=log_config))
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not uv.started and time.time() < deadline:
        time.sleep(0.05)
    assert uv.started, "uvicorn did not start"
    try:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}{target}?expires=1&%73ignature=SIGNATURE-VALUE-456", timeout=10)
        except urllib.error.HTTPError:
            pass
        time.sleep(0.3)
    finally:
        uv.should_exit = True
        thread.join(timeout=10)
    out, err = capfd.readouterr()
    return out + err


@pytest.mark.parametrize("target", [f"/download/{UNKNOWN_ID}", f"/{UNKNOWN_ID}", "/download-but-not-really/x", "/mcp"])
def test_a_signature_is_kept_out_of_the_access_log_on_any_path(capfd, target):
    """The download route, and a mangled signed URL (a doubled slash read as a host, a base
    URL joined wrong) that still carries a live signature on a path under neither prefix."""
    from uvicorn.config import LOGGING_CONFIG

    stock = _serve_once_and_capture(LOGGING_CONFIG, capfd, target)
    assert "SIGNATURE-VALUE-456" in stock, f"negative control: stock access log did not show the URL: {stock!r}"

    served = _serve_once_and_capture(server.uvicorn_log_config(), capfd, target)

    assert f"GET {target}" in served, f"the access line itself must survive: {served!r}"
    assert "SIGNATURE-VALUE-456" not in served
