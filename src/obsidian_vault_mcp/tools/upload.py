"""Signed direct binary upload: request a short-lived HMAC-signed URL, then POST the bytes
straight to it.

The client uploads the bytes (the server fetches nothing -- no SSRF surface), which avoids
the base64 / MCP-argument-size limits of ``vault_write_binary`` for large files. Two parts:

- ``vault_request_upload_url(...)`` -- an MCP tool that validates the target against the same
  binary allowlist and returns a short-lived signed URL plus an ``upload_id``.
- ``commit_direct_upload(...)`` -- called by the ``POST /upload/{id}`` route (wired in
  ``server.py``). That route is bearer-exempt because the HMAC signature in the URL IS the
  authorization: it is single-use, short-lived, and constant-time compared.

The staging directory lives OUTSIDE the vault (so the vault tools cannot touch it) and holds
only a per-upload ``metadata.json``; the uploaded bytes are written into the vault via
``write_bytes_atomic`` only after every check passes.
"""

import hashlib
import hmac
import json
import logging
import shutil
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode

from .. import config
from ..serialization import dumps
from ..vault import write_bytes_atomic
from .write import _validate_binary_target

logger = logging.getLogger(__name__)

DIRECT_UPLOAD_TYPE = "direct"
_STALE_CLEANUP_SECONDS = 24 * 60 * 60
_UPLOAD_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"


def _upload_root() -> Path:
    root = config.UPLOAD_STAGING_DIR
    root.mkdir(parents=True, exist_ok=True)
    return root


def _upload_paths(upload_id: str) -> tuple[Path, Path]:
    if not upload_id or any(ch not in _UPLOAD_ID_ALPHABET for ch in upload_id):
        raise ValueError("Invalid upload_id")
    upload_dir = _upload_root() / upload_id
    return upload_dir, upload_dir / "metadata.json"


def _upload_secret() -> str:
    secret = config.VAULT_UPLOAD_URL_SECRET or config.VAULT_MCP_TOKEN
    if not secret:
        raise ValueError(
            "VAULT_UPLOAD_URL_SECRET or VAULT_MCP_TOKEN must be configured for direct uploads"
        )
    return secret


def _canonical(metadata: dict, expires_at: int) -> str:
    """The stable string the upload URL signs over."""
    return "\n".join(
        [
            metadata["upload_id"],
            metadata["path"],
            metadata["media_type"],
            str(metadata["max_size_bytes"]),
            str(expires_at),
            metadata.get("expected_sha256") or "",
        ]
    )


def _signature(metadata: dict, expires_at: int) -> str:
    payload = _canonical(metadata, expires_at).encode("utf-8")
    return hmac.new(_upload_secret().encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_sha256_hex(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise ValueError("expected_sha256 must be a 64-character hex SHA-256 digest")
    return normalized


def _write_json_atomic(path: Path, payload: dict) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp_path.replace(path)


def _cleanup_stale_uploads() -> None:
    cutoff = time.time() - _STALE_CLEANUP_SECONDS
    try:
        entries = list(_upload_root().iterdir())
    except OSError:
        return
    for entry in entries:
        if not entry.is_dir():
            continue
        try:
            if entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry)
        except OSError:
            logger.warning("Could not remove stale upload staging dir: %s", entry)


def _load_upload(upload_id: str) -> tuple[dict, Path]:
    upload_dir, metadata_path = _upload_paths(upload_id)
    if not upload_dir.exists() or not metadata_path.exists():
        raise ValueError(f"Unknown upload_id: {upload_id}")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    return metadata, metadata_path


def vault_request_upload_url(
    path: str,
    media_type: str,
    max_size_bytes: int,
    overwrite: bool = False,
    create_dirs: bool = True,
    expected_sha256: str | None = None,
    ttl_seconds: int | None = None,
) -> str:
    """Create a short-lived signed HTTP URL for a direct binary upload."""
    try:
        _cleanup_stale_uploads()
        resolved = _validate_binary_target(path, media_type)
        if max_size_bytes <= 0:
            return dumps({"error": "max_size_bytes must be greater than 0", "path": path})
        if max_size_bytes > config.MAX_BINARY_SIZE:
            return dumps(
                {
                    "error": f"max_size_bytes {max_size_bytes} exceeds limit of {config.MAX_BINARY_SIZE} bytes",
                    "path": path,
                    "media_type": media_type,
                }
            )
        if resolved.exists() and not overwrite:
            return dumps(
                {
                    "error": f"File already exists: {path}. Set overwrite=true to replace it.",
                    "path": path,
                    "media_type": media_type,
                }
            )

        normalized_sha256 = _validate_sha256_hex(expected_sha256) if expected_sha256 else None
        requested_ttl = ttl_seconds if ttl_seconds is not None else config.VAULT_UPLOAD_URL_TTL_SECONDS
        max_ttl = max(1, config.VAULT_UPLOAD_URL_MAX_TTL_SECONDS)
        effective_ttl = max(1, min(requested_ttl, max_ttl))
        now = int(time.time())
        expires_at = now + effective_ttl
        upload_id = str(uuid.uuid4())
        upload_dir, metadata_path = _upload_paths(upload_id)
        upload_dir.mkdir(parents=True, exist_ok=False)
        metadata = {
            "type": DIRECT_UPLOAD_TYPE,
            "upload_id": upload_id,
            "path": path,
            "media_type": media_type.strip().lower(),
            "max_size_bytes": max_size_bytes,
            "overwrite": overwrite,
            "create_dirs": create_dirs,
            "expected_sha256": normalized_sha256,
            "created_at": now,
            "expires_at": expires_at,
            "completed_at": None,
        }
        _write_json_atomic(metadata_path, metadata)
        signature = _signature(metadata, expires_at)
        base_url = config.VAULT_MCP_PUBLIC_URL or f"http://127.0.0.1:{config.VAULT_MCP_PORT}"
        upload_url = f"{base_url}/upload/{upload_id}?{urlencode({'expires': str(expires_at), 'signature': signature})}"
        return dumps(
            {
                "upload_id": upload_id,
                "upload_url": upload_url,
                "expires_at": expires_at,
                "expires_in_seconds": effective_ttl,
                "path": path,
                "media_type": media_type,
                "max_size_bytes": max_size_bytes,
                "method": "POST",
                "curl": f'curl -X POST -H "Content-Type: {media_type}" --data-binary @/path/to/file "{upload_url}"',
            }
        )
    except ValueError as e:
        return dumps({"error": str(e), "path": path, "media_type": media_type})
    except Exception as e:  # noqa: BLE001
        logger.error("vault_request_upload_url error for %s: %s", path, e)
        return dumps({"error": str(e), "path": path, "media_type": media_type})


def commit_direct_upload(
    upload_id: str,
    content: bytes,
    content_type: str,
    expires: str,
    signature: str,
) -> tuple[dict, int]:
    """Validate and commit a signed direct HTTP upload. Returns (result, http_status)."""
    try:
        metadata, metadata_path = _load_upload(upload_id)
        if metadata.get("type") != DIRECT_UPLOAD_TYPE:
            return {"error": "Upload id is not a direct upload session", "upload_id": upload_id}, 400

        try:
            expires_at = int(expires)
        except (TypeError, ValueError):
            return {"error": "Invalid expires parameter", "upload_id": upload_id}, 400
        if expires_at != int(metadata["expires_at"]):
            return {"error": "Upload expiry mismatch", "upload_id": upload_id}, 403
        if time.time() > expires_at:
            return {"error": "Upload URL has expired", "upload_id": upload_id}, 410
        expected_signature = _signature(metadata, expires_at)
        if not signature or not hmac.compare_digest(signature, expected_signature):
            return {"error": "Invalid upload signature", "upload_id": upload_id}, 403
        if metadata.get("completed_at"):
            return {"error": "Upload URL has already been used", "upload_id": upload_id}, 409

        media_type = metadata["media_type"]
        normalized_content_type = (content_type or "").split(";", 1)[0].strip().lower()
        if normalized_content_type != media_type:
            return {
                "error": f"Content-Type '{normalized_content_type}' does not match requested media_type '{media_type}'",
                "upload_id": upload_id,
                "media_type": media_type,
            }, 415
        if not content:
            return {"error": "Upload body is empty", "upload_id": upload_id}, 400
        if len(content) > metadata["max_size_bytes"]:
            return {
                "error": f"Uploaded content exceeds max_size_bytes of {metadata['max_size_bytes']} bytes",
                "upload_id": upload_id,
                "size": len(content),
            }, 413
        if len(content) > config.MAX_BINARY_SIZE:
            return {
                "error": f"Uploaded content exceeds server limit of {config.MAX_BINARY_SIZE} bytes",
                "upload_id": upload_id,
                "size": len(content),
            }, 413

        actual_sha256 = _sha256_bytes(content)
        expected_sha256 = metadata.get("expected_sha256")
        if expected_sha256 and actual_sha256 != expected_sha256:
            return {
                "error": "Upload checksum mismatch",
                "upload_id": upload_id,
                "expected_sha256": expected_sha256,
                "actual_sha256": actual_sha256,
            }, 422

        # Re-validate the target at commit time (allowlist + vault confinement).
        resolved = _validate_binary_target(metadata["path"], media_type)
        if resolved.exists() and not metadata["overwrite"]:
            return {
                "error": f"File already exists: {metadata['path']}. Set overwrite=true to replace it.",
                "upload_id": upload_id,
                "path": metadata["path"],
            }, 409

        is_new, size = write_bytes_atomic(
            metadata["path"],
            content,
            create_dirs=metadata["create_dirs"],
            overwrite=metadata["overwrite"],
        )
        metadata["completed_at"] = int(time.time())
        metadata["size"] = size
        metadata["sha256"] = actual_sha256
        _write_json_atomic(metadata_path, metadata)
        return {
            "upload_id": upload_id,
            "path": metadata["path"],
            "created": is_new,
            "size": size,
            "media_type": media_type,
            "sha256": actual_sha256,
        }, 201 if is_new else 200
    except ValueError as e:
        return {"error": str(e), "upload_id": upload_id}, 400
    except Exception as e:  # noqa: BLE001
        logger.error("direct upload commit error for %s: %s", upload_id, e)
        return {"error": str(e), "upload_id": upload_id}, 500
