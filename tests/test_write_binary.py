"""Tests for vault_write_binary: the base64 → vault binary-write capability."""

import base64
import json

import pytest

from obsidian_vault_mcp import config
from obsidian_vault_mcp.models import VaultWriteBinaryInput
from obsidian_vault_mcp.tools.write import vault_write_binary

# A few bytes that need not be a real PNG — only media_type + extension are checked.
_PNG_BYTES = b"\x89PNG\r\n\x1a\n fake-image-bytes"
_PNG_B64 = base64.b64encode(_PNG_BYTES).decode()


def test_writes_allowed_binary(vault_dir):
    result = json.loads(vault_write_binary("assets/pic.png", _PNG_B64, "image/png"))
    assert "error" not in result, result
    assert result["created"] is True
    assert result["size"] == len(_PNG_BYTES)
    assert (vault_dir / "assets" / "pic.png").read_bytes() == _PNG_BYTES


def test_rejects_invalid_base64(vault_dir):
    result = json.loads(vault_write_binary("pic.png", "not!base64!", "image/png"))
    assert "Invalid base64" in result["error"]
    assert not (vault_dir / "pic.png").exists()


def test_rejects_unsupported_media_type(vault_dir):
    result = json.loads(vault_write_binary("bin.exe", _PNG_B64, "application/x-msdownload"))
    assert "Unsupported media_type" in result["error"]
    assert not (vault_dir / "bin.exe").exists()


def test_rejects_svg_active_content(vault_dir):
    # SVG is intentionally NOT in the allowlist (it can carry <script>/onload).
    result = json.loads(vault_write_binary("a.svg", _PNG_B64, "image/svg+xml"))
    assert "Unsupported media_type" in result["error"]
    assert not (vault_dir / "a.svg").exists()


def test_rejects_extension_media_type_mismatch(vault_dir):
    # .png path but declared as a PDF — the allowlist must catch the mismatch.
    result = json.loads(vault_write_binary("pic.png", _PNG_B64, "application/pdf"))
    assert "is not allowed for media_type" in result["error"]
    assert not (vault_dir / "pic.png").exists()


def test_rejects_path_traversal(vault_dir):
    result = json.loads(vault_write_binary("../escape.png", _PNG_B64, "image/png"))
    assert "error" in result
    assert not (vault_dir.parent / "escape.png").exists()


def test_overwrite_guard(vault_dir):
    first = json.loads(vault_write_binary("pic.png", _PNG_B64, "image/png"))
    assert first["created"] is True

    blocked = json.loads(vault_write_binary("pic.png", _PNG_B64, "image/png"))
    assert "already exists" in blocked["error"]

    allowed = json.loads(vault_write_binary("pic.png", _PNG_B64, "image/png", overwrite=True))
    assert "error" not in allowed
    assert allowed["created"] is False


def test_enforces_size_cap(vault_dir, monkeypatch):
    monkeypatch.setattr(config, "MAX_BINARY_SIZE", 8)
    payload = base64.b64encode(b"x" * 64).decode()
    result = json.loads(vault_write_binary("big.png", payload, "image/png"))
    assert "exceeds limit" in result["error"]
    assert not (vault_dir / "big.png").exists()


def test_model_rejects_empty_path_and_extra_fields():
    with pytest.raises(Exception):
        VaultWriteBinaryInput(path="", data=_PNG_B64, media_type="image/png")
    with pytest.raises(Exception):
        VaultWriteBinaryInput(path="a.png", data=_PNG_B64, media_type="image/png", bogus=1)
