"""Signed direct download, tested through what serves it: build_app() and the registered tool.

Every client-facing test requests the URL through the MCP tool registration and fetches the
bytes through the app build_app() returns, bearer middleware included, with no
Authorization header. The cases come from what reaches the route from outside: method,
path shape, query string, the grant's state, and the file changing between the moment the
URL is issued and the moment it is redeemed.
"""

import asyncio
import hashlib
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

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
    monkeypatch.setattr(config, "DOWNLOAD_STAGING_DIR", tmp_path / "downloads")
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


def client() -> TestClient:
    return TestClient(server.build_app(), raise_server_exceptions=False)


# --- The route works through build_app, without a bearer token -----------------------------

def test_download_through_build_app_serves_the_exact_bytes():
    grant = request_url()

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 200, response.text
    assert response.content == PNG
    assert grant["size"] == len(PNG)
    assert grant["sha256"] == hashlib.sha256(PNG).hexdigest()
    assert response.headers["content-type"] == "image/png"
    assert response.headers["content-length"] == str(len(PNG))


def test_url_is_single_use():
    grant = request_url()
    c = client()

    first = c.get(local_path(grant["download_url"]))
    second = c.get(local_path(grant["download_url"]))

    assert first.status_code == 200
    assert second.status_code == 409, second.text
    assert second.content != PNG


def test_a_file_larger_than_one_chunk_streams_whole(vault_dir):
    big = os.urandom(3 * 1024 * 1024 + 17)
    (vault_dir / "big.bin").write_bytes(big)
    grant = request_url("big.bin")

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 200
    assert response.content == big
    assert hashlib.sha256(response.content).hexdigest() == grant["sha256"]


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


def test_a_non_ascii_filename_is_carried_without_breaking_the_header(vault_dir):
    (vault_dir / 'Prüfung "final".pdf').write_bytes(b"%PDF-1.4\n")
    grant = request_url('Prüfung "final".pdf')

    response = client().get(local_path(grant["download_url"]))

    disposition = response.headers["content-disposition"]
    assert response.status_code == 200
    assert "filename*=UTF-8''Pr%C3%BCfung%20%22final%22.pdf" in disposition
    assert 'filename="Pr_fung _final_.pdf"' in disposition


def test_a_range_header_does_not_buy_a_partial_read_that_keeps_the_url():
    grant = request_url()
    c = client()

    ranged = c.get(local_path(grant["download_url"]), headers={"Range": "bytes=0-0"})
    again = c.get(local_path(grant["download_url"]))

    assert ranged.status_code == 200 and ranged.content == PNG
    assert again.status_code == 409


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


def test_the_tool_refuses_a_file_over_the_cap(vault_dir, monkeypatch):
    monkeypatch.setattr(config, "VAULT_DOWNLOAD_MAX_BYTES", len(PNG) - 1)

    payload = call_tool(path="bilder/scan.png")

    assert "error" in payload and "download_url" not in payload, payload


def test_the_lifetime_is_clamped_to_the_maximum(monkeypatch):
    monkeypatch.setattr(config, "VAULT_DOWNLOAD_URL_MAX_TTL_SECONDS", 60)

    grant = request_url(ttl_seconds=86400)

    assert grant["expires_in_seconds"] == 60


# --- The grant ---------------------------------------------------------------------------------

def _with_query(grant: dict, **replace) -> str:
    parsed = urlparse(grant["download_url"])
    params = dict(part.split("=", 1) for part in parsed.query.split("&"))
    params.update(replace)
    return parsed.path + "?" + "&".join(f"{k}={v}" for k, v in params.items())


@pytest.mark.parametrize(
    "replace,status",
    [
        ({"signature": "0" * 64}, 403),
        ({"signature": "%C3%A9"}, 403),
        ({"signature": ""}, 403),
        ({"expires": "1"}, 403),
        ({"expires": "soon"}, 400),
    ],
)
def test_a_bad_grant_is_refused_and_does_not_spend_the_url(replace, status):
    grant = request_url()
    c = client()

    refused = c.get(_with_query(grant, **replace))
    good = c.get(local_path(grant["download_url"]))

    assert refused.status_code == status, refused.text
    assert refused.content != PNG
    assert good.status_code == 200 and good.content == PNG


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


@pytest.mark.parametrize("download_id", [UNKNOWN_ID, "abc", "A" * 64])
def test_an_unknown_or_malformed_id_is_404(download_id):
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


def test_a_head_with_a_bearer_token_neither_serves_nor_spends_the_url():
    grant = request_url()
    c = client()

    head = c.head(local_path(grant["download_url"]), headers={"Authorization": f"Bearer {SECRET_TOKEN}"})
    get = c.get(local_path(grant["download_url"]))

    assert head.status_code == 405
    assert get.status_code == 200 and get.content == PNG


# --- The file changes between issue and redemption ---------------------------------------------

def test_a_file_changed_in_place_is_not_served(vault_dir):
    grant = request_url()
    target = vault_dir / "bilder" / "scan.png"
    target.write_bytes(PNG[::-1])
    os.utime(target, ns=(time.time_ns(), time.time_ns() + 10_000_000))

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 409, response.text
    assert response.content != PNG[::-1]


def test_a_replacement_with_the_same_size_and_mtime_is_not_served(vault_dir):
    """Only the inode differs: the pinned identity is the one thing that catches this."""
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
    """Same name, same size, outside the vault: only the pinned identity tells them apart."""
    grant = request_url()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "scan.png").write_bytes(b"X" * len(PNG))
    (vault_dir / "bilder").rename(vault_dir / "bilder-alt")
    (vault_dir / "bilder").symlink_to(elsewhere)

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code in (404, 409), response.text
    assert b"X" * 64 not in response.content


def test_a_file_hardlinked_after_issue_is_not_served(vault_dir, tmp_path):
    grant = request_url()
    os.link(vault_dir / "bilder" / "scan.png", tmp_path / "second-name.png")

    response = client().get(local_path(grant["download_url"]))

    assert response.status_code == 409, response.text


def test_a_refused_file_does_not_spend_the_url(vault_dir):
    grant = request_url()
    target = vault_dir / "bilder" / "scan.png"
    target.rename(vault_dir / "weg.png")

    gone = client().get(local_path(grant["download_url"]))
    (vault_dir / "weg.png").rename(target)
    back = client().get(local_path(grant["download_url"]))

    assert gone.status_code == 404
    assert back.status_code == 200 and back.content == PNG


# --- Single use under a race, and the handle is closed --------------------------------------

def test_two_racing_requests_get_the_file_once():
    grant = request_url()
    query = urlparse(grant["download_url"]).query
    params = dict(part.split("=", 1) for part in query.split("&"))
    results = []
    barrier = threading.Barrier(8)

    def redeem():
        barrier.wait()
        payload, status, fd = download_mod.open_signed_download(grant["download_id"], params["expires"], params["signature"])
        if fd is not None:
            os.close(fd)
        results.append(status)

    threads = [threading.Thread(target=redeem) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(results) == [200] + [409] * 7, results


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="needs /proc to count open descriptors")
def test_the_file_handle_is_closed_after_serving_and_after_a_refusal(vault_dir):
    c = client()
    before = len(os.listdir("/proc/self/fd"))

    target = vault_dir / "bilder" / "scan.png"
    for i in range(5):
        grant = request_url()
        assert c.get(local_path(grant["download_url"])).status_code == 200
        assert c.get(local_path(grant["download_url"])).status_code == 409
        # Refused after the file was opened: the identity no longer matches.
        changed = request_url()
        os.utime(target, ns=(time.time_ns(), time.time_ns() + (i + 1) * 10_000_000))
        assert c.get(local_path(changed["download_url"])).status_code == 409

    assert len(os.listdir("/proc/self/fd")) <= before


# --- /download is reserved ----------------------------------------------------------------------

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


# --- Staging, audit, sweep ------------------------------------------------------------------------

def test_staging_is_owner_only():
    grant = request_url()
    grant_dir = config.DOWNLOAD_STAGING_DIR / grant["download_id"]

    assert (config.DOWNLOAD_STAGING_DIR.stat().st_mode & 0o777) == 0o700
    assert (grant_dir.stat().st_mode & 0o777) == 0o700
    assert ((grant_dir / "metadata.json").stat().st_mode & 0o777) == 0o600


def _records(audit_log):
    if not audit_log.exists():
        return []
    return [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_issue_and_download_are_audited_as_reads_when_reads_are_audited(download_env, monkeypatch):
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", True)
    grant = request_url()
    client().get(local_path(grant["download_url"]))
    client().get(local_path(grant["download_url"]))  # refused: not audited

    ops = [(r["operation"], r["target_path"], r["operation_status"]) for r in _records(download_env)]

    assert ops == [
        ("vault_request_download_url", "bilder/scan.png", "success"),
        ("vault_download", "bilder/scan.png", "success"),
    ], ops


def test_nothing_is_audited_when_reads_are_not(download_env, monkeypatch):
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", False)
    grant = request_url()
    client().get(local_path(grant["download_url"]))

    assert _records(download_env) == []


def test_stale_sweep_removes_old_grant_dirs_and_nothing_else(tmp_path):
    root = config.DOWNLOAD_STAGING_DIR
    root.mkdir(parents=True, exist_ok=True)
    old = root / UNKNOWN_ID
    old.mkdir()
    other = root / "not-a-grant"
    other.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep", encoding="utf-8")
    link = root / "1f0e0d0c-0b0a-4908-8706-050403020100"
    link.symlink_to(victim, target_is_directory=True)
    stamp = time.time() - 3 * 24 * 3600
    for entry in (old, other):
        os.utime(entry, (stamp, stamp))

    download_mod.cleanup_stale_downloads()

    assert not old.exists()
    assert other.exists()
    assert (victim / "keep.txt").exists()


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
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}{target}?expires=1&%73ignature=SIGNATURE-VALUE-456", timeout=10
            )
        except urllib.error.HTTPError:
            pass
        time.sleep(0.3)
    finally:
        uv.should_exit = True
        thread.join(timeout=10)
    out, err = capfd.readouterr()
    return out + err


def test_access_log_does_not_record_the_download_signature(capfd):
    from uvicorn.config import LOGGING_CONFIG

    stock = _serve_once_and_capture(LOGGING_CONFIG, capfd)
    assert "SIGNATURE-VALUE-456" in stock, f"negative control: stock access log did not show the URL: {stock!r}"

    served = _serve_once_and_capture(server.uvicorn_log_config(), capfd)

    assert "GET /download/" in served, f"the access line itself must survive: {served!r}"
    assert "SIGNATURE-VALUE-456" not in served


@pytest.mark.parametrize("target", [f"/{UNKNOWN_ID}", "/download-but-not-really/x", "/mcp"])
def test_a_signature_on_another_path_is_kept_out_of_the_access_log(capfd, target):
    """A mangled signed URL (a doubled slash read as a host, a base URL joined wrong) still
    carries a live signature on a path outside both prefixes."""
    from uvicorn.config import LOGGING_CONFIG

    stock = _serve_once_and_capture(LOGGING_CONFIG, capfd, target)
    assert "SIGNATURE-VALUE-456" in stock, f"negative control: stock access log did not show the URL: {stock!r}"

    served = _serve_once_and_capture(server.uvicorn_log_config(), capfd, target)

    assert f"GET {target}" in served, f"the access line itself must survive: {served!r}"
    assert "SIGNATURE-VALUE-456" not in served
