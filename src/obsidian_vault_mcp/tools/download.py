"""Signed direct download: request a short-lived HMAC-signed URL, then GET the bytes from it.

The read counterpart of the signed upload. ``vault_read`` returns text: it refuses an image
or a spreadsheet and gives a PDF only as extracted text. Here the client receives a URL and
fetches the file's bytes itself, for example with curl from a shell, so they never pass
through the conversation.

Two parts:

- ``vault_request_download_url(path)``, an MCP tool: resolves the path with the same guard
  ``vault_read`` uses, opens the file and signs its identity (device, inode, size, mtime)
  into the URL together with the path and the expiry.
- the ``GET /download/{id}`` route in ``server.py``: bearer-exempt, because the signature
  is the authorization. ``open_signed_download`` checks the signature and the expiry,
  resolves the path again, opens it once, and accepts the open handle only if it is the
  file the URL was issued for. The route streams from that handle, so a path swapped
  after the check (a symlinked parent, a replaced file) serves nothing.

The grant lives entirely in the URL; the server keeps no state. A URL can be fetched
again until it expires, which a short lifetime bounds. The open handle does not freeze the
file's contents: a write into the same file after the open is served as written.
"""

import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import shlex
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
_CHUNK = 1024 * 1024
# A random id per URL, signed with it: it names the URL in the server log, where the
# query string is redacted. uuid4 only.
_DOWNLOAD_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_IDENTITY = ("device", "inode", "size", "mtime_ns")
# The final component is opened without following a symlink; a symlink put in place of
# the file after the guard resolved the path fails the open.
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)


def _download_secret() -> str:
    # No fallback to the upload secret or the bearer token: the signing key is its own
    # secret, and without it the whole feature is off (config.signed_download_enabled).
    if not config.VAULT_DOWNLOAD_URL_SECRET:
        raise ValueError("VAULT_DOWNLOAD_URL_SECRET must be set for signed downloads")
    return config.VAULT_DOWNLOAD_URL_SECRET


def _signature(grant: dict) -> str:
    # JSON, not a joined string: a path may contain any character, a newline included,
    # and the encoding must not let one field run into the next.
    payload = json.dumps(
        [grant["download_id"], grant["path"], *(grant[key] for key in _IDENTITY), grant["expires"]],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hmac.new(_download_secret().encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _identity(st: os.stat_result) -> dict:
    return {"device": st.st_dev, "inode": st.st_ino, "size": st.st_size, "mtime_ns": st.st_mtime_ns}


def _open_vault_file(path: str) -> tuple[int, os.stat_result]:
    """Open a vault file for reading through the vault_read guard; return (fd, fstat).

    The guard resolves the path and refuses dotfiles, paths outside the vault and
    hardlinks. The handle is checked again from fstat, which describes what was actually
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
    """Create a short-lived signed URL for downloading one vault file."""
    try:
        fd, st = _open_vault_file(path)
        os.close(fd)
        requested_ttl = ttl_seconds if ttl_seconds is not None else config.VAULT_DOWNLOAD_URL_TTL_SECONDS
        effective_ttl = max(1, min(requested_ttl, max(1, config.VAULT_DOWNLOAD_URL_MAX_TTL_SECONDS)))
        expires = int(time.time()) + effective_ttl
        grant = {"download_id": str(uuid.uuid4()), "path": path, **_identity(st), "expires": expires}
        query = urlencode({**{key: grant[key] for key in ("path", *_IDENTITY, "expires")}, "signature": _signature(grant)})
        base_url = (config.VAULT_MCP_PUBLIC_URL or f"http://127.0.0.1:{config.VAULT_MCP_PORT}").rstrip("/")
        download_url = f"{base_url}{config.DOWNLOAD_ROUTE_PREFIX}/{grant['download_id']}?{query}"
        filename = Path(path).name
        return dumps(
            {
                "download_id": grant["download_id"],
                "download_url": download_url,
                "expires_at": expires,
                "expires_in_seconds": effective_ttl,
                "path": path,
                "filename": filename,
                "media_type": _media_type(path),
                "size": st.st_size,
                "method": "GET",
                # Quoted for a POSIX shell: a note may be named $(id).txt, and an agent
                # runs this line as given.
                "curl": f"curl -fsS -o {shlex.quote(filename)} {shlex.quote(download_url)}",
            }
        )
    except FileNotFoundError:
        return dumps({"error": f"File not found: {path}", "path": path})
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except Exception as e:  # noqa: BLE001
        logger.error("vault_request_download_url error for %s: %s", path, e)
        return dumps({"error": str(e), "path": path})


def _read_grant(download_id: str, query) -> tuple[dict | None, tuple[dict, int] | None]:
    """Parse the signed fields from the query string; (grant, None) or (None, refusal)."""
    try:
        grant = {
            "download_id": download_id,
            "path": query["path"],
            **{key: int(query[key]) for key in (*_IDENTITY, "expires")},
        }
    except (KeyError, ValueError):
        return None, ({"error": "Malformed download URL", "download_id": download_id}, 400)
    return grant, None


def open_signed_download(download_id: str, query) -> tuple[dict, int, int | None]:
    """Check a signed download URL and open its file; return (payload, status, fd).

    ``query`` is the request's query parameters. On success the status is 200, the payload
    describes the file, and fd is an open handle on exactly the file the URL was issued
    for; the caller streams from it and closes it. On any refusal fd is None and nothing
    is left open.
    """
    if _DOWNLOAD_ID.fullmatch(download_id) is None:
        return {"error": "Unknown download id", "download_id": download_id}, 404, None
    grant, refusal = _read_grant(download_id, query)
    if refusal is not None:
        return (*refusal, None)
    signature = query.get("signature", "")
    # Compared as bytes: compare_digest raises TypeError on a non-ASCII str, which a client
    # can put in the query string (signature=%C3%A9) and turn into a 500.
    if not signature or not hmac.compare_digest(signature.encode("utf-8"), _signature(grant).encode("ascii")):
        return {"error": "Invalid download signature", "download_id": download_id}, 403, None
    if time.time() > grant["expires"]:
        return {"error": "Download URL has expired", "download_id": download_id}, 410, None

    try:
        fd, st = _open_vault_file(grant["path"])
    except FileNotFoundError:
        return {"error": "File is no longer there", "download_id": download_id}, 404, None
    except (ValueError, OSError):
        # A policy refusal (now outside the vault, hardlinked, a symlink in place of the
        # file) or an open that failed: not the file the URL was issued for.
        return {"error": "File changed since the URL was issued", "download_id": download_id}, 409, None
    if _identity(st) != {key: grant[key] for key in _IDENTITY}:
        os.close(fd)
        return {"error": "File changed since the URL was issued", "download_id": download_id}, 409, None
    return {
        "download_id": download_id,
        "path": grant["path"],
        "filename": Path(grant["path"]).name,
        "media_type": _media_type(grant["path"]),
        "size": st.st_size,
    }, 200, fd


def read_chunk(fd: int, size: int = _CHUNK) -> bytes:
    return os.read(fd, size)
