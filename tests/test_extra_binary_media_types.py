"""Operator-added binary media types (#100).

The built-in allowlist accepts images and PDF. VAULT_EXTRA_BINARY_MEDIA_TYPES_JSON adds
types (Office files are the case that asked for it), never removes one, and cannot name a
text extension the write tools own. Writes go through the registered vault_write_binary
and through the signed upload route in build_app(); the startup check runs in a child
process with the real environment variable.
"""

import asyncio
import base64
import json
import os
import subprocess
import sys
from urllib.parse import urlparse

import pytest
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth as auth_module
from obsidian_vault_mcp import config, server

DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
OFFICE = {DOCX: [".docx"], XLSX: [".xlsx"]}
ZIP_BYTES = b"PK\x03\x04" + bytes(range(256)) * 4
PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(64))


def call_tool(name: str, arguments: dict) -> dict:
    result = asyncio.run(server.mcp.call_tool(name, arguments))
    if isinstance(result, tuple):
        result = result[0]
    return json.loads("".join(getattr(block, "text", "") for block in result))


def write_binary(path: str, media_type: str, data: bytes) -> dict:
    return call_tool("vault_write_binary", {"path": path, "media_type": media_type,
                                            "data": base64.b64encode(data).decode()})


@pytest.fixture
def office(monkeypatch):
    monkeypatch.setattr(config, "EXTRA_BINARY_MEDIA_TYPES", config.parse_extra_binary_media_types(json.dumps(OFFICE)))


def test_without_the_setting_office_files_are_refused(vault_dir):
    """Control: the built-in list is unchanged by default."""
    result = write_binary("a.docx", DOCX, ZIP_BYTES)

    assert "Unsupported media_type" in result.get("error", ""), result
    assert not (vault_dir / "a.docx").exists()


def test_the_setting_admits_the_named_types(vault_dir, office):
    for path, media_type in (("a.docx", DOCX), ("b.xlsx", XLSX)):
        result = write_binary(path, media_type, ZIP_BYTES)
        assert result.get("created") is True, result
        assert (vault_dir / path).read_bytes() == ZIP_BYTES


def test_the_built_in_types_stay(vault_dir, office):
    assert write_binary("p.png", "image/png", PNG).get("created") is True


def test_extras_add_to_a_built_in_type_without_replacing_it(vault_dir, monkeypatch):
    monkeypatch.setattr(config, "EXTRA_BINARY_MEDIA_TYPES",
                        config.parse_extra_binary_media_types('{"image/jpeg": [".jpe"]}'))

    assert write_binary("a.jpe", "image/jpeg", b"\xff\xd8\xff\xd9").get("created") is True
    assert write_binary("b.jpg", "image/jpeg", b"\xff\xd8\xff\xd9").get("created") is True


def test_the_extension_must_still_match_the_media_type(vault_dir, office):
    result = write_binary("a.xlsx", DOCX, ZIP_BYTES)

    assert "is not allowed for media_type" in result.get("error", ""), result
    assert not (vault_dir / "a.xlsx").exists()


def test_a_signed_upload_accepts_an_added_type(vault_dir, tmp_path, monkeypatch, office):
    monkeypatch.setattr(config, "UPLOAD_STAGING_DIR", tmp_path / "uploads")
    monkeypatch.setattr(config, "VAULT_UPLOAD_URL_SECRET", "upload-secret")
    monkeypatch.setattr(auth_module, "VAULT_MCP_TOKEN", "bearer")
    grant = call_tool("vault_request_upload_url", {"path": "docs/bericht.docx", "media_type": DOCX,
                                                   "max_size_bytes": len(ZIP_BYTES)})
    assert "upload_url" in grant, grant
    url = urlparse(grant["upload_url"])

    response = TestClient(server.build_app(), raise_server_exceptions=False).post(
        f"{url.path}?{url.query}", content=ZIP_BYTES, headers={"Content-Type": DOCX})

    assert response.status_code == 201, response.text
    assert (vault_dir / "docs" / "bericht.docx").read_bytes() == ZIP_BYTES


def test_a_signed_upload_refuses_it_without_the_setting(vault_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "UPLOAD_STAGING_DIR", tmp_path / "uploads")
    monkeypatch.setattr(config, "VAULT_UPLOAD_URL_SECRET", "upload-secret")

    grant = call_tool("vault_request_upload_url", {"path": "docs/bericht.docx", "media_type": DOCX,
                                                   "max_size_bytes": len(ZIP_BYTES)})

    assert "Unsupported media_type" in grant.get("error", ""), grant


def start(raw: str | None) -> subprocess.CompletedProcess:
    """Run the startup check server.main() runs, in a fresh interpreter with the variable set."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("VAULT_")}
    env["VAULT_PATH"] = os.getcwd()
    if raw is not None:
        env["VAULT_EXTRA_BINARY_MEDIA_TYPES_JSON"] = raw
    return subprocess.run([sys.executable, "-c", "from obsidian_vault_mcp.config import validate_config; validate_config()"],
                          env=env, capture_output=True, text=True)


@pytest.mark.parametrize("raw,fragment", [
    ("{not json", "not valid JSON"),
    ('[".docx"]', "must be a JSON object"),
    ('{"a/b": ".docx"}', "non-empty list"),
    ('{"a/b": []}', "non-empty list"),
    ('{"a/b": ["docx"]}', "leading dot"),
    ('{"text/markdown": [".md"]}', "cannot be a binary type"),
    ('{"a/b": [".canvas"]}', "cannot be a binary type"),
    ('{"a/b": [".MD"]}', "cannot be a binary type"),
    ('{"image/svg+xml": [".svg"]}', "cannot be a binary type"),
    ('{"notatype": [".x"]}', "type/subtype"),
])
def test_a_bad_setting_stops_startup_with_its_name(raw, fragment):
    result = start(raw)

    assert result.returncode != 0
    assert "VAULT_EXTRA_BINARY_MEDIA_TYPES_JSON" in result.stderr and fragment in result.stderr, result.stderr[-400:]


@pytest.mark.parametrize("raw", [None, "", json.dumps(OFFICE)])
def test_a_good_or_absent_setting_starts(raw):
    result = start(raw)

    assert result.returncode == 0, result.stderr[-400:]
