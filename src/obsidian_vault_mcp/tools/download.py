"""Signed direct download: request a short-lived HMAC-signed URL, then GET the bytes from it.

The read counterpart of the signed upload. ``vault_read`` returns text: it refuses an image
or a spreadsheet and gives a PDF only as extracted text. Here the client receives a URL and
fetches the file's bytes itself, for example with curl from a shell, so they never pass
through the conversation.

Two parts:

- ``vault_request_download_url(path)``, an MCP tool: resolves the path with the same guard
  ``vault_read`` uses, opens the file once, hashes it from that handle, and records its
  identity (device, inode, size, mtime) in a grant signed together with the URL.
- the ``GET /download/{id}`` route in ``server.py``: bearer-exempt, because the signature
  is the authorization. ``open_signed_download`` checks the grant, resolves the path
  again, opens it once, and accepts the open handle only if it is the same file the grant
  was issued for. The route streams from that handle, so a path swapped after the check
  (a symlinked parent, a replaced file) cannot change what is served.

Single use, enforced by an atomic claim. There is no HEAD and no Range: a request that
reads part of a file without spending the URL would make "single use" a matter of how the
client asks.

The staging dir holds only grants, never file bytes, and lives outside the vault.
"""

import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import shutil
import stat
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode

from .. import config
from ..serialization import dumps
from ..vault import resolve_vault_read_path

logger = logging.getLogger(__name__)

AUDIT_OPERATION = "vault_download"
_STALE_CLEANUP_SECONDS = 24 * 60 * 60
_HASH_CHUNK = 1024 * 1024
# uuid4 ids only. The sweep relies on this: it removes nothing that is not named like one.
_DOWNLOAD_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
# The final component is opened without following a symlink. Not every platform has the
# flag; there the identity check below still refuses a file that is not the granted one.
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)


def _download_root() -> Path:
    # 0700: a grant names a vault path. None of that is for other users on the box.
    root = config.DOWNLOAD_STAGING_DIR
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def download_dir(download_id: str) -> Path:
    if not isinstance(download_id, str) or _DOWNLOAD_ID.fullmatch(download_id) is None:
        raise ValueError("Invalid download_id")
    return _download_root() / download_id


def _download_secret() -> str:
    # No fallback to the upload secret or the bearer token: the signing key is its own
    # secret, and without it the whole feature is off (config.signed_download_enabled).
    if not config.VAULT_DOWNLOAD_URL_SECRET:
        raise ValueError("VAULT_DOWNLOAD_URL_SECRET must be set for signed downloads")
    return config.VAULT_DOWNLOAD_URL_SECRET


def _canonical(metadata: dict, expires_at: int) -> str:
    """The string the download URL signs: which file, exactly, and until when."""
    return "\n".join(
        [
            metadata["download_id"],
            metadata["path"],
            str(metadata["size"]),
            metadata["sha256"],
            str(metadata["device"]),
            str(metadata["inode"]),
            str(metadata["mtime_ns"]),
            str(expires_at),
        ]
    )


def _signature(metadata: dict, expires_at: int) -> str:
    payload = _canonical(metadata, expires_at).encode("utf-8")
    return hmac.new(_download_secret().encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _write_json_atomic(path: Path, payload: dict) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    try:
        tmp_path.chmod(0o600)
    except OSError:  # no-op where file modes are meaningless
        pass
    tmp_path.replace(path)


def cleanup_stale_downloads(now: float | None = None) -> None:
    """Remove grant dirs older than a day.

    Only real directories named like a download id are candidates, and a symlink is never
    followed or removed: the staging dir is operator-configurable.
    """
    cutoff = (now if now is not None else time.time()) - _STALE_CLEANUP_SECONDS
    try:
        entries = list(_download_root().iterdir())
    except OSError:
        return
    for entry in entries:
        if _DOWNLOAD_ID.fullmatch(entry.name) is None or entry.is_symlink() or not entry.is_dir():
            continue
        try:
            if entry.lstat().st_mtime < cutoff:
                shutil.rmtree(entry)
        except OSError:
            logger.warning("Could not remove stale download staging dir: %s", entry)


def _identity(st: os.stat_result) -> dict:
    return {"device": st.st_dev, "inode": st.st_ino, "size": st.st_size, "mtime_ns": st.st_mtime_ns}


def _open_vault_file(path: str) -> tuple[int, os.stat_result]:
    """Open a vault file for reading through the vault_read guard; return (fd, fstat).

    The guard resolves the path, refuses dotfiles, paths outside the vault and hardlinks.
    The returned handle is checked again from fstat, which describes what was actually
    opened rather than what the path pointed at a moment earlier.
    """
    resolved = resolve_vault_read_path(path)
    fd = os.open(resolved, _OPEN_FLAGS)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Not a regular file: {path}")
        if st.st_nlink > 1:
            raise ValueError(f"Refusing hardlinked file: {path}")
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def _media_type(path: str) -> str:
    guessed, _encoding = mimetypes.guess_type(path)
    return guessed or "application/octet-stream"


def vault_request_download_url(path: str, ttl_seconds: int | None = None) -> str:
    """Create a short-lived signed URL for one direct download."""
    try:
        cleanup_stale_downloads()
        fd, st = _open_vault_file(path)
        try:
            if st.st_size > config.VAULT_DOWNLOAD_MAX_BYTES:
                return dumps(
                    {
                        "error": f"File is {st.st_size} bytes, over the {config.VAULT_DOWNLOAD_MAX_BYTES} bytes a download URL serves",
                        "path": path,
                    }
                )
            digest = hashlib.sha256()
            while chunk := os.read(fd, _HASH_CHUNK):
                digest.update(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        if _identity(after) != _identity(st):
            return dumps({"error": f"File changed while it was being read: {path}. Try again.", "path": path})

        requested_ttl = ttl_seconds if ttl_seconds is not None else config.VAULT_DOWNLOAD_URL_TTL_SECONDS
        effective_ttl = max(1, min(requested_ttl, max(1, config.VAULT_DOWNLOAD_URL_MAX_TTL_SECONDS)))
        now = int(time.time())
        expires_at = now + effective_ttl
        download_id = str(uuid.uuid4())
        staging = download_dir(download_id)
        staging.mkdir(parents=True, exist_ok=False, mode=0o700)
        metadata = {
            "download_id": download_id,
            "path": path,
            "filename": Path(path).name,
            "media_type": _media_type(path),
            "sha256": digest.hexdigest(),
            **_identity(st),
            "created_at": now,
            "expires_at": expires_at,
            "completed_at": None,
        }
        _write_json_atomic(staging / "metadata.json", metadata)
        signature = _signature(metadata, expires_at)
        base_url = (config.VAULT_MCP_PUBLIC_URL or f"http://127.0.0.1:{config.VAULT_MCP_PORT}").rstrip("/")
        query = urlencode({"expires": str(expires_at), "signature": signature})
        download_url = f"{base_url}{config.DOWNLOAD_ROUTE_PREFIX}/{download_id}?{query}"
        return dumps(
            {
                "download_id": download_id,
                "download_url": download_url,
                "expires_at": expires_at,
                "expires_in_seconds": effective_ttl,
                "path": path,
                "filename": metadata["filename"],
                "media_type": metadata["media_type"],
                "size": metadata["size"],
                "sha256": metadata["sha256"],
                "method": "GET",
                "single_use": True,
                "curl": f'curl -fsS -o "{metadata["filename"]}" "{download_url}"',
            }
        )
    except FileNotFoundError:
        return dumps({"error": f"File not found: {path}", "path": path})
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except Exception as e:  # noqa: BLE001
        logger.error("vault_request_download_url error for %s: %s", path, e)
        return dumps({"error": str(e), "path": path})


def _load_metadata(download_id: str) -> tuple[dict, Path]:
    metadata_path = download_dir(download_id) / "metadata.json"
    if not metadata_path.is_file():
        raise FileNotFoundError(download_id)
    return json.loads(metadata_path.read_text(encoding="utf-8")), metadata_path


def _check_grant(download_id: str, metadata: dict, expires: str, signature: str) -> tuple[dict, int] | None:
    try:
        expires_at = int(expires)
    except (TypeError, ValueError):
        return {"error": "Invalid expires parameter", "download_id": download_id}, 400
    expected_signature = _signature(metadata, int(metadata["expires_at"]))
    # Compared as bytes: compare_digest raises TypeError on a non-ASCII str, which a client
    # can put in the query string (signature=%C3%A9) and turn into a 500.
    if (
        expires_at != int(metadata["expires_at"])
        or not signature
        or not hmac.compare_digest(signature.encode("utf-8"), expected_signature.encode("ascii"))
    ):
        return {"error": "Invalid download signature", "download_id": download_id}, 403
    if time.time() > expires_at:
        return {"error": "Download URL has expired", "download_id": download_id}, 410
    if metadata.get("completed_at"):
        return {"error": "Download URL has already been used", "download_id": download_id}, 409
    return None


def open_signed_download(download_id: str, expires: str, signature: str) -> tuple[dict, int, int | None]:
    """Check a signed download URL and open the granted file; return (payload, status, fd).

    On success the status is 200, the payload is the grant, and fd is an open handle on
    exactly the file the grant was issued for; the caller streams from it and closes it.
    On any refusal fd is None and nothing is left open. An unknown and a malformed id both
    answer 404, so the route leaks nothing about which ids exist.

    The URL is spent only once the file has been opened and matched: a refusal before that
    (a bad signature, a file that changed) leaves an unused grant unused.
    """
    try:
        metadata, metadata_path = _load_metadata(download_id)
    except (ValueError, FileNotFoundError, OSError, json.JSONDecodeError):
        return {"error": "Unknown download id", "download_id": download_id}, 404, None
    refusal = _check_grant(download_id, metadata, expires, signature)
    if refusal is not None:
        return (*refusal, None)

    try:
        fd, st = _open_vault_file(metadata["path"])
    except FileNotFoundError:
        return {"error": "File is no longer there", "download_id": download_id}, 404, None
    except (ValueError, OSError):
        # A policy refusal (now outside the vault, hardlinked, a symlink in place of the
        # file) or an open that failed: not the file the grant was issued for.
        return {"error": "File changed since the URL was issued", "download_id": download_id}, 409, None
    if _identity(st) != {key: metadata[key] for key in ("device", "inode", "size", "mtime_ns")}:
        os.close(fd)
        return {"error": "File changed since the URL was issued", "download_id": download_id}, 409, None

    # Claim the grant atomically: of two requests racing on one URL exactly one proceeds.
    try:
        (metadata_path.parent / "claimed").mkdir()
    except FileExistsError:
        os.close(fd)
        return {"error": "Download URL has already been used", "download_id": download_id}, 409, None
    except OSError:
        os.close(fd)
        return {"error": "Download could not be started", "download_id": download_id}, 500, None
    metadata["completed_at"] = int(time.time())
    try:
        _write_json_atomic(metadata_path, metadata)
    except OSError:
        # The claim marker already spends the URL; the record is informational.
        logger.warning("Could not record download completion: %s", download_id)
    return metadata, 200, fd


def read_chunk(fd: int, size: int = _HASH_CHUNK) -> bytes:
    return os.read(fd, size)
