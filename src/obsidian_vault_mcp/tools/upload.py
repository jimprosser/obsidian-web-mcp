"""Signed direct upload: request a short-lived HMAC-signed URL, then POST the bytes to it.

Why this exists next to ``vault_write_binary``: that tool carries the file base64-encoded
inside an MCP tool argument, so the whole file travels through the model's context. A
few megabytes is already more than clients carry in practice. Here the client only
receives a URL and sends the bytes straight to the server; the model never sees them.

Two parts:

- ``vault_request_upload_url(...)``, an MCP tool: validates the target against the binary
  allowlist and returns a signed URL for one upload.
- the ``POST /upload/{id}`` route in ``server.py``: bearer-exempt, because the signature is
  the authorization. It calls ``validate_upload_grant`` before reading any body bytes,
  streams the body into a temp file here in the staging dir under a hard cap, and calls
  ``commit_direct_upload`` to check the grant again and place the file.

The staging dir lives outside the vault, so vault tools cannot reach it.
"""

import hashlib
import hmac
import json
import logging
import re
import shutil
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode

from .. import config
from ..audit import build_audit_record, should_audit_operation, snapshot_path, write_audit_record
from ..serialization import dumps
from ..vault import write_file_from_path_atomic
from ..write_events import fire_write
from .write import _validate_binary_target

logger = logging.getLogger(__name__)

AUDIT_OPERATION = "vault_upload"
_STALE_CLEANUP_SECONDS = 24 * 60 * 60
# uuid4 ids only. The sweep relies on this: it removes nothing that is not named like one.
_UPLOAD_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


def _upload_root() -> Path:
    # 0700: a grant decides what gets written where, and metadata.json carries the target
    # path. None of that is for other users on the box.
    root = config.UPLOAD_STAGING_DIR
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def upload_dir(upload_id: str) -> Path:
    if not isinstance(upload_id, str) or _UPLOAD_ID.fullmatch(upload_id) is None:
        raise ValueError("Invalid upload_id")
    return _upload_root() / upload_id


def _upload_secret() -> str:
    # No fallback to the bearer token: the signing key is its own secret, and without it
    # the whole feature is off (config.signed_upload_enabled).
    if not config.VAULT_UPLOAD_URL_SECRET:
        raise ValueError("VAULT_UPLOAD_URL_SECRET must be set for signed uploads")
    return config.VAULT_UPLOAD_URL_SECRET


def _canonical(metadata: dict, expires_at: int) -> str:
    """The string the upload URL signs: everything that decides what gets written where."""
    return "\n".join(
        [
            metadata["upload_id"],
            metadata["path"],
            metadata["media_type"],
            str(metadata["max_size_bytes"]),
            str(int(metadata["overwrite"])),
            str(expires_at),
            metadata.get("expected_sha256") or "",
        ]
    )


def _signature(metadata: dict, expires_at: int) -> str:
    payload = _canonical(metadata, expires_at).encode("utf-8")
    return hmac.new(_upload_secret().encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _validate_sha256_hex(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise ValueError("expected_sha256 must be a 64-character hex SHA-256 digest")
    return normalized


def _write_json_atomic(path: Path, payload: dict) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    try:
        tmp_path.chmod(0o600)
    except OSError:  # no-op where file modes are meaningless
        pass
    tmp_path.replace(path)


def cleanup_stale_uploads(now: float | None = None) -> None:
    """Remove staging dirs older than a day.

    Only real directories named like an upload id are candidates, and a symlink is never
    followed or removed: the staging dir is operator-configurable, and a sweep that
    rmtree'd whatever it found there would delete anything someone pointed it at.
    """
    cutoff = (now if now is not None else time.time()) - _STALE_CLEANUP_SECONDS
    try:
        entries = list(_upload_root().iterdir())
    except OSError:
        return
    for entry in entries:
        if _UPLOAD_ID.fullmatch(entry.name) is None or entry.is_symlink() or not entry.is_dir():
            continue
        try:
            if entry.lstat().st_mtime < cutoff:
                shutil.rmtree(entry)
        except OSError:
            logger.warning("Could not remove stale upload staging dir: %s", entry)


def vault_request_upload_url(
    path: str,
    media_type: str,
    max_size_bytes: int,
    overwrite: bool = False,
    create_dirs: bool = True,
    expected_sha256: str | None = None,
    ttl_seconds: int | None = None,
) -> str:
    """Create a short-lived signed URL for one direct upload."""
    try:
        cleanup_stale_uploads()
        resolved = _validate_binary_target(path, media_type)
        if max_size_bytes <= 0:
            return dumps({"error": "max_size_bytes must be greater than 0", "path": path})
        if max_size_bytes > config.VAULT_UPLOAD_MAX_BYTES:
            return dumps(
                {
                    "error": f"max_size_bytes {max_size_bytes} exceeds limit of {config.VAULT_UPLOAD_MAX_BYTES} bytes",
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
        effective_ttl = max(1, min(requested_ttl, max(1, config.VAULT_UPLOAD_URL_MAX_TTL_SECONDS)))
        now = int(time.time())
        expires_at = now + effective_ttl
        upload_id = str(uuid.uuid4())
        staging = upload_dir(upload_id)
        staging.mkdir(parents=True, exist_ok=False, mode=0o700)
        metadata = {
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
        _write_json_atomic(staging / "metadata.json", metadata)
        signature = _signature(metadata, expires_at)
        base_url = (config.VAULT_MCP_PUBLIC_URL or f"http://127.0.0.1:{config.VAULT_MCP_PORT}").rstrip("/")
        query = urlencode({"expires": str(expires_at), "signature": signature})
        upload_url = f"{base_url}{config.UPLOAD_ROUTE_PREFIX}/{upload_id}?{query}"
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


def _load_metadata(upload_id: str) -> tuple[dict, Path]:
    metadata_path = upload_dir(upload_id) / "metadata.json"
    if not metadata_path.is_file():
        raise FileNotFoundError(upload_id)
    return json.loads(metadata_path.read_text(encoding="utf-8")), metadata_path


def _check_grant(upload_id: str, metadata: dict, expires: str, signature: str) -> tuple[dict, int] | None:
    try:
        expires_at = int(expires)
    except (TypeError, ValueError):
        return {"error": "Invalid expires parameter", "upload_id": upload_id}, 400
    expected_signature = _signature(metadata, int(metadata["expires_at"]))
    # Compared as bytes: compare_digest raises TypeError on a non-ASCII str, which a client
    # can put in the query string (signature=%C3%A9) and turn into a 500.
    if (
        expires_at != int(metadata["expires_at"])
        or not signature
        or not hmac.compare_digest(signature.encode("utf-8"), expected_signature.encode("ascii"))
    ):
        return {"error": "Invalid upload signature", "upload_id": upload_id}, 403
    if time.time() > expires_at:
        return {"error": "Upload URL has expired", "upload_id": upload_id}, 410
    if metadata.get("completed_at"):
        return {"error": "Upload URL has already been used", "upload_id": upload_id}, 409
    return None


def validate_upload_grant(upload_id: str, expires: str, signature: str) -> tuple[dict, int]:
    """Check id, signature, expiry and single use without touching the request body.

    Returns (metadata, 200) for a usable grant, otherwise (error payload, status). An
    unknown id and a malformed id both answer 404, so the route leaks nothing about
    which ids exist.
    """
    try:
        metadata, _ = _load_metadata(upload_id)
    except (ValueError, FileNotFoundError, OSError, json.JSONDecodeError):
        return {"error": "Unknown upload id", "upload_id": upload_id}, 404
    refusal = _check_grant(upload_id, metadata, expires, signature)
    if refusal is not None:
        return refusal
    return metadata, 200


def commit_direct_upload(
    upload_id: str,
    staged_path: Path,
    sha256: str,
    content_type: str,
    expires: str,
    signature: str,
) -> tuple[dict, int]:
    """Check the grant again, validate the streamed file, and place it in the vault.

    The grant is re-checked here, immediately before the write: two requests on the same
    URL can both pass the route's first check, and only this one sees whether the other
    already completed. Every committed attempt on a valid grant is audited and a
    successful one fires a write event, like any other mutation.
    """
    try:
        metadata, metadata_path = _load_metadata(upload_id)
    except (ValueError, FileNotFoundError, OSError, json.JSONDecodeError):
        return {"error": "Unknown upload id", "upload_id": upload_id}, 404
    refusal = _check_grant(upload_id, metadata, expires, signature)
    if refusal is not None:
        return refusal

    # Claim the grant atomically. mkdir either creates the marker or fails, so of two
    # requests racing on one URL exactly one proceeds. A commit that is refused before
    # anything is written releases the claim, so a wrong Content-Type does not burn the URL.
    claim = metadata_path.parent / "claimed"
    try:
        claim.mkdir()
    except FileExistsError:
        return {"error": "Upload URL has already been used", "upload_id": upload_id}, 409

    target = metadata["path"]
    # Only snapshotted when it will be recorded: snapshot_path hashes the whole existing
    # target, up to VAULT_UPLOAD_MAX_BYTES, and a failure there must not leave the grant
    # claimed with nothing written.
    auditing = should_audit_operation(AUDIT_OPERATION)
    before = snapshot_path(target) if auditing else None
    result, status = _commit(upload_id, metadata, metadata_path, staged_path, sha256, content_type)
    if "error" in result and not metadata.get("completed_at"):
        try:
            claim.rmdir()
        except OSError:
            pass
    if auditing:
        write_audit_record(
            build_audit_record(
                operation=AUDIT_OPERATION,
                target_path=target,
                before=before,
                after=snapshot_path(target) if "error" not in result else None,
                operation_status="error" if "error" in result else "success",
                error=result.get("error"),
            )
        )
    if "error" not in result:
        fire_write("created" if result["created"] else "updated", [target])
    return result, status


def _commit(
    upload_id: str, metadata: dict, metadata_path: Path, staged_path: Path, sha256: str, content_type: str
) -> tuple[dict, int]:
    try:
        media_type = metadata["media_type"]
        normalized_content_type = (content_type or "").split(";", 1)[0].strip().lower()
        if normalized_content_type != media_type:
            return {
                "error": f"Content-Type '{normalized_content_type}' does not match requested media_type '{media_type}'",
                "upload_id": upload_id,
                "media_type": media_type,
            }, 415
        size = staged_path.stat().st_size
        if size == 0:
            return {"error": "Upload body is empty", "upload_id": upload_id}, 400
        if size > metadata["max_size_bytes"]:
            return {
                "error": f"Uploaded content exceeds max_size_bytes of {metadata['max_size_bytes']} bytes",
                "upload_id": upload_id,
                "size": size,
            }, 413
        expected_sha256 = metadata.get("expected_sha256")
        if expected_sha256 and sha256 != expected_sha256:
            return {
                "error": "Upload checksum mismatch",
                "upload_id": upload_id,
                "expected_sha256": expected_sha256,
                "actual_sha256": sha256,
            }, 422

        # Re-validated at commit time: allowlist and vault confinement.
        resolved = _validate_binary_target(metadata["path"], media_type)
        if resolved.exists() and not metadata["overwrite"]:
            return {
                "error": f"File already exists: {metadata['path']}. Set overwrite=true to replace it.",
                "upload_id": upload_id,
                "path": metadata["path"],
            }, 409

        is_new, size = write_file_from_path_atomic(
            metadata["path"],
            staged_path,
            create_dirs=metadata["create_dirs"],
            overwrite=metadata["overwrite"],
        )
        metadata["completed_at"] = int(time.time())
        metadata["size"] = size
        metadata["sha256"] = sha256
        _write_json_atomic(metadata_path, metadata)
        return {
            "upload_id": upload_id,
            "path": metadata["path"],
            "created": is_new,
            "size": size,
            "media_type": media_type,
            "sha256": sha256,
        }, 201 if is_new else 200
    except FileExistsError as e:
        return {"error": str(e), "upload_id": upload_id, "path": metadata.get("path")}, 409
    except ValueError as e:
        return {"error": str(e), "upload_id": upload_id}, 400
    except Exception as e:  # noqa: BLE001
        logger.error("direct upload commit error for %s: %s", upload_id, e)
        return {"error": "Upload could not be committed", "upload_id": upload_id}, 500
