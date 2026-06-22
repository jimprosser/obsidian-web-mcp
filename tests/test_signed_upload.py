"""Tests for the signed direct-upload logic (request + commit).

Exercises the logic layer directly (the thin POST /upload/{id} route is a separate concern):
request a signed URL, then drive commit_direct_upload with the signature/expiry from it,
including the abuse cases (bad signature, expired, replay, oversize, media-type, checksum).
"""

import json
from urllib.parse import parse_qs, urlparse

import pytest

from obsidian_vault_mcp import config
from obsidian_vault_mcp.tools import upload as upload_mod
from obsidian_vault_mcp.tools.upload import commit_direct_upload, vault_request_upload_url


@pytest.fixture(autouse=True)
def _upload_env(vault_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "UPLOAD_STAGING_DIR", tmp_path / "uploads")
    monkeypatch.setattr(config, "VAULT_UPLOAD_URL_SECRET", "test-secret")
    return vault_dir


def _request(path, media_type, max_size, **kw):
    return json.loads(vault_request_upload_url(path, media_type, max_size, **kw))


def _sig_expires(req):
    q = parse_qs(urlparse(req["upload_url"]).query)
    return q["signature"][0], q["expires"][0]


def test_request_and_commit_happy_path(vault_dir):
    req = _request("assets/x.png", "image/png", 1000)
    assert "error" not in req, req
    sig, expires = _sig_expires(req)
    result, code = commit_direct_upload(req["upload_id"], b"PNGBYTES", "image/png", expires, sig)
    assert "error" not in result, result
    assert code == 201 and result["created"] is True
    assert (vault_dir / "assets" / "x.png").read_bytes() == b"PNGBYTES"


def test_bad_signature_rejected(vault_dir):
    req = _request("x.png", "image/png", 1000)
    _sig, expires = _sig_expires(req)
    result, code = commit_direct_upload(req["upload_id"], b"data", "image/png", expires, "deadbeef")
    assert code == 403 and "signature" in result["error"]
    assert not (vault_dir / "x.png").exists()


def test_expired_rejected(vault_dir, monkeypatch):
    req = _request("x.png", "image/png", 1000, ttl_seconds=2)
    sig, expires = _sig_expires(req)
    monkeypatch.setattr(upload_mod.time, "time", lambda: int(expires) + 10)
    result, code = commit_direct_upload(req["upload_id"], b"data", "image/png", expires, sig)
    assert code == 410 and "expired" in result["error"].lower()


def test_single_use_replay_rejected(vault_dir):
    req = _request("x.png", "image/png", 1000)
    sig, expires = _sig_expires(req)
    first, code1 = commit_direct_upload(req["upload_id"], b"data", "image/png", expires, sig)
    assert code1 in (200, 201) and "error" not in first
    second, code2 = commit_direct_upload(req["upload_id"], b"data", "image/png", expires, sig)
    assert code2 == 409 and "already been used" in second["error"]


def test_oversize_rejected(vault_dir):
    req = _request("x.png", "image/png", 8)  # max_size_bytes = 8
    sig, expires = _sig_expires(req)
    result, code = commit_direct_upload(req["upload_id"], b"x" * 64, "image/png", expires, sig)
    assert code == 413 and "exceeds" in result["error"]
    assert not (vault_dir / "x.png").exists()


def test_media_type_mismatch_rejected(vault_dir):
    req = _request("x.png", "image/png", 1000)
    sig, expires = _sig_expires(req)
    result, code = commit_direct_upload(req["upload_id"], b"data", "application/pdf", expires, sig)
    assert code == 415 and "does not match" in result["error"]


def test_checksum_mismatch_rejected(vault_dir):
    import hashlib
    wanted = hashlib.sha256(b"the-right-bytes").hexdigest()
    req = _request("x.png", "image/png", 1000, expected_sha256=wanted)
    sig, expires = _sig_expires(req)
    result, code = commit_direct_upload(req["upload_id"], b"the-wrong-bytes", "image/png", expires, sig)
    assert code == 422 and "checksum" in result["error"]


def test_request_rejects_svg(vault_dir):
    req = _request("x.svg", "image/svg+xml", 1000)
    assert "Unsupported media_type" in req["error"]


def test_request_rejects_oversize_max(vault_dir):
    req = _request("x.png", "image/png", config.MAX_BINARY_SIZE + 1)
    assert "exceeds limit" in req["error"]


def test_unknown_upload_id_rejected(vault_dir):
    result, code = commit_direct_upload("not-a-real-id", b"data", "image/png", "0", "x")
    assert code == 400 and "Unknown upload_id" in result["error"]


# --- wiring: the route is registered and bearer-exempt ---

def test_upload_route_registered_and_app_builds(monkeypatch):
    monkeypatch.setattr(config, "VAULT_MCP_TOKEN", "secret-token")
    from obsidian_vault_mcp.server import build_app
    app = build_app()
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/upload/{upload_id}" in paths


def test_upload_path_is_bearer_exempt_end_to_end(vault_dir, monkeypatch):
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse, PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from obsidian_vault_mcp import auth as auth_module

    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "secret-token")

    async def up(request):
        body = await request.body()
        result, code = commit_direct_upload(
            request.path_params["upload_id"],
            body,
            request.headers.get("content-type", ""),
            request.query_params.get("expires", ""),
            request.query_params.get("signature", ""),
        )
        return JSONResponse(result, status_code=code)

    async def root(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/upload/{upload_id}", up, methods=["POST"]), Route("/", root)])
    app.add_middleware(auth_module.BearerAuthMiddleware)
    client = TestClient(app)

    # Control: a normal route still demands the bearer token.
    assert client.get("/").status_code == 401

    # POST /upload/{id} WITHOUT a bearer token must reach commit (HMAC is the auth).
    req = json.loads(vault_request_upload_url("up.png", "image/png", 1000))
    sig, expires = _sig_expires(req)
    r = client.post(
        f"/upload/{req['upload_id']}?expires={expires}&signature={sig}",
        content=b"PNGBYTES",
        headers={"content-type": "image/png"},
    )
    assert r.status_code == 201, r.text
    assert (vault_dir / "up.png").read_bytes() == b"PNGBYTES"

    # A bad signature is rejected (403) -- reached the handler, never a 401.
    req2 = json.loads(vault_request_upload_url("up2.png", "image/png", 1000))
    _sig2, expires2 = _sig_expires(req2)
    bad = client.post(
        f"/upload/{req2['upload_id']}?expires={expires2}&signature=deadbeef",
        content=b"x",
        headers={"content-type": "image/png"},
    )
    assert bad.status_code == 403
