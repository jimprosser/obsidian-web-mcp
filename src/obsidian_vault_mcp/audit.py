"""Append-only JSON-lines audit log for vault mutations.

When VAULT_AUDIT_LOG_PATH is set, every vault mutation appends one JSON record to that
file: a UTC timestamp, a SHA-256 hash of the bearer token (never the token itself), the
operation, the target path, and the size + checksum of the target before and after the
change. Read/search operations are logged too when VAULT_AUDIT_LOG_INCLUDE_READS is on.

Auditing is off unless a log path is configured. At startup the path is validated as
writable AND rejected if it resolves inside the vault (where the vault tools could rewrite
it), so a misconfigured path fails the server closed. At runtime the log is best-effort:
a failure to write a record is logged but never alters the tool result -- the audit trail
must not be able to break a write.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config
from .context import current_request_context
from .serialization import dumps
from .vault import resolve_vault_path

logger = logging.getLogger(__name__)

# Operations that change the vault. Always audited when a log path is configured.
MUTATION_OPERATIONS = {
    "vault_write",
    "vault_write_binary",
    "vault_edit",
    "vault_append",
    "vault_batch_frontmatter_update",
    "vault_move",
    "vault_delete",
    "vault_canvas_add_node",
    "vault_canvas_add_edge",
    "vault_daily_note_append",
    "vault_upload",
}

# Read/search operations. Audited only when VAULT_AUDIT_LOG_INCLUDE_READS is enabled.
READ_OPERATIONS = {
    "vault_read",
    "vault_batch_read",
    "vault_search",
    "vault_search_frontmatter",
    "vault_list",
    "vault_canvas_read",
    "vault_daily_note_read",
}

# Mutations whose result reports per-file outcomes; audited one record per file.
BATCH_OPERATIONS = {"vault_batch_frontmatter_update"}


def audit_enabled() -> bool:
    """True when append-only audit logging is configured."""
    return bool(config.VAULT_AUDIT_LOG_PATH)


def read_audit_enabled() -> bool:
    """True when read/search operations should also be audited."""
    return audit_enabled() and bool(config.VAULT_AUDIT_LOG_INCLUDE_READS)


# Operations an extension registered, name -> "read" | "mutation". The built-in sets
# above stay closed; this is how a tool the host does not know about gets the same
# treatment (issue #91). Registered before serving, read during request handling.
_registered_operations: dict[str, str] = {}
_OPERATION_KINDS = ("read", "mutation")
# The character set and length MCP allows for tool names. An operation name is written into
# every record, so whitespace, control characters or an unbounded length would either make
# the declaration silently miss the name the tool later passes, or clutter the log.
_OPERATION_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")


def _lookalike_key(name: str) -> str:
    return name.casefold().replace("-", "_").replace(".", "_")


def register_audit_operation(operation: str, kind: str = "mutation") -> None:
    """Declare an extension tool's operation name to the audit log.

    Without this, should_audit_operation answers False for any name the host does not
    know, so an extension tool is invisible in the log however the operator configures
    it. ``kind="mutation"`` records every call; ``kind="read"`` records only when
    VAULT_AUDIT_LOG_INCLUDE_READS is on, like the built-in read tools.

    Registering the same name twice with the same kind is a no-op, so an extension that
    is loaded twice does not fail; a different kind is a conflict and raises.

    The name must use the characters MCP allows in tool names (letters, digits, ``_``,
    ``-``, ``.``, at most 128), and must not be a built-in name in another spelling
    (``VAULT_WRITE``, ``vault-write``): in the log it would read as the built-in tool.
    """
    if not isinstance(operation, str) or not _OPERATION_NAME.fullmatch(operation):
        raise ValueError(
            "operation must be 1-128 characters of letters, digits, '_', '-' or '.', "
            f"got {operation!r}"
        )
    if kind not in _OPERATION_KINDS:
        raise ValueError(f"kind must be one of {_OPERATION_KINDS}, got {kind!r}")
    built_ins = MUTATION_OPERATIONS | READ_OPERATIONS
    if operation in built_ins:
        raise ValueError(f"{operation!r} is a built-in operation and cannot be re-registered")
    key = _lookalike_key(operation)
    for built_in in built_ins:
        if _lookalike_key(built_in) == key:
            raise ValueError(
                f"{operation!r} would read as the built-in operation {built_in!r} in the log"
            )
    existing = _registered_operations.get(operation)
    if existing is not None and existing != kind:
        raise ValueError(f"{operation!r} is already registered as {existing!r}, not {kind!r}")
    _registered_operations[operation] = kind


def operation_kind(operation: str) -> str | None:
    """"read", "mutation", or None for an operation the audit log does not cover."""
    if operation in MUTATION_OPERATIONS:
        return "mutation"
    if operation in READ_OPERATIONS:
        return "read"
    return _registered_operations.get(operation)


def should_audit_operation(operation: str) -> bool:
    """True when this operation should emit a record under the current config.

    False whenever auditing is off, so the wrapper is a true passthrough (no snapshot
    work) on the default path.
    """
    if not audit_enabled():
        return False
    kind = operation_kind(operation)
    if kind == "mutation":
        return True
    return kind == "read" and read_audit_enabled()


def audit_log_path() -> Path:
    return Path(config.VAULT_AUDIT_LOG_PATH).expanduser()


def audit_path_writable(path: Path | None = None) -> bool:
    """True when the audit log can be written (creating intermediate dirs if needed).

    An existing log must be a writable file. Otherwise the log is creatable when the
    nearest existing ancestor is a writable directory -- write_audit_record mkdirs the
    intermediate dirs. A path whose parent is a regular file is rejected.
    """
    path = path or audit_log_path()
    try:
        if path.exists():
            return path.is_file() and os.access(path, os.W_OK)
        ancestor = path.parent
        while not ancestor.exists():
            if ancestor.parent == ancestor:
                return False
            ancestor = ancestor.parent
        return ancestor.is_dir() and os.access(ancestor, os.W_OK)
    except OSError:
        return False


def audit_path_inside_vault() -> bool:
    """True when the configured audit log resolves inside the vault.

    A same-vault log is just another file the vault tools can reach: resolve_vault_path
    only blocks traversal and dotfiles, so an authenticated caller could overwrite it via
    vault_write or relocate it via vault_delete, defeating the append-only integrity
    premise. Such a path is rejected at startup (see server.main).
    """
    if not audit_enabled():
        return False
    try:
        log = audit_log_path().resolve()
        vault = config.VAULT_PATH.resolve()
    except OSError:
        return False
    return log == vault or vault in log.parents


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _hash_value(value: str | None) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_path(path: Any) -> dict[str, Any]:
    """Capture (size, checksum) for a vault-relative path; nulls when absent or invalid.

    Routes through resolve_vault_path so a path that escapes the vault is treated as
    absent rather than read.
    """
    empty: dict[str, Any] = {"size": None, "checksum": None}
    if not isinstance(path, str) or not path:
        return empty
    try:
        resolved = resolve_vault_path(path)
    except ValueError:
        return empty
    if not resolved.is_file():
        return empty
    return {"size": resolved.stat().st_size, "checksum": _sha256_file(resolved)}


def before_target_path(operation: str, context: dict[str, Any]) -> Any:
    """The path to snapshot before a mutation runs."""
    if operation == "vault_move":
        return context.get("source")
    return context.get("path") or context.get("source")


def infer_target_path(operation: str, context: dict[str, Any], result: dict[str, Any] | None = None) -> Any:
    """Best-effort target path from the call context and the parsed result payload."""
    result = result or {}
    if operation == "vault_move":
        return result.get("destination") or context.get("destination")
    if operation == "vault_batch_frontmatter_update":
        results = result.get("results")
        if isinstance(results, list):
            paths = [item.get("path") for item in results if isinstance(item, dict) and item.get("path")]
            if paths:
                return paths
    return result.get("path") or context.get("path") or context.get("source")


def build_audit_record(
    *,
    operation: str,
    target_path: Any,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    operation_status: str = "success",
    error: str | None = None,
) -> dict[str, Any]:
    """Build one normalized audit record from the current request context."""
    ctx = current_request_context()
    before = before or {"size": None, "checksum": None}
    after = after or {"size": None, "checksum": None}
    return {
        "timestamp": _now_utc().isoformat(),
        "token_id_hash": _hash_value(ctx.get("principal")),
        "client_id": ctx.get("client"),
        "operation": operation,
        "target_path": target_path,
        "size_before": before.get("size"),
        "size_after": after.get("size"),
        "checksum_before": before.get("checksum"),
        "checksum_after": after.get("checksum"),
        "request_id": ctx.get("request_id") or uuid.uuid4().hex,
        "operation_status": operation_status,
        "error": error,
    }


def write_audit_record(record: dict[str, Any]) -> bool:
    """Append one JSON record. A write failure is logged and swallowed (best-effort)."""
    if not audit_enabled():
        return False
    try:
        path = audit_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        line = dumps(record, sort_keys=True) + "\n"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        return True
    except Exception as exc:
        logger.error("Audit log write failed: %s", exc)
        return False


def _parse_tool_result(result: str) -> dict:
    """Parse a tool's JSON result into a dict, or {} when it is not a JSON object."""
    try:
        payload = json.loads(result)
    except (ValueError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def run_audited(operation: str, func, **context) -> str:
    """Run a tool and emit audit records when auditing covers this operation.

    Public so an extension tool can be audited the same way a built-in one is, after
    declaring its name with register_audit_operation (issue #91)::

        register_audit_operation("vault_fts_search", kind="read")

        def vault_fts_search(query: str) -> str:
            return run_audited("vault_fts_search", lambda: _search(query), path=None)

    ``context`` carries the call's arguments; ``path`` (or ``source``) is what gets
    snapshotted for a mutation, and the result's ``path`` wins when the tool reports one.

    A straight passthrough when auditing is off (no log path) or the operation is a read
    and read-audit is disabled, so there is no cost on the default path. For mutations the
    target is snapshotted (size + checksum) before and after; reads capture the target as
    it is read. Batch mutations emit one record per file (see _run_audited_batch). An
    audit-write failure is swallowed inside write_audit_record so the trail can never break
    the tool result.
    """
    if not should_audit_operation(operation):
        return func()

    if operation in BATCH_OPERATIONS:
        return _run_audited_batch(operation, func, context)

    is_mutation = operation_kind(operation) == "mutation"
    before = snapshot_path(before_target_path(operation, context)) if is_mutation else None

    try:
        result = func()
    except Exception:
        write_audit_record(build_audit_record(
            operation=operation,
            target_path=infer_target_path(operation, context),
            before=before,
            operation_status="error",
            error="tool exception",
        ))
        raise

    parsed = _parse_tool_result(result)
    target_path = infer_target_path(operation, context, parsed)
    status = "error" if "error" in parsed else "success"
    error = parsed.get("error") if status == "error" else None
    if is_mutation:
        record = build_audit_record(
            operation=operation, target_path=target_path, before=before,
            after=snapshot_path(target_path), operation_status=status, error=error,
        )
    else:
        record = build_audit_record(
            operation=operation, target_path=target_path,
            before=snapshot_path(target_path), operation_status=status, error=error,
        )
    write_audit_record(record)
    return result


def _run_audited_batch(operation: str, func, context: dict) -> str:
    """Audit a batch mutation as one record per file with correct per-file status.

    The batch tools report per-file outcomes inside ``results`` (some files can fail while
    the call as a whole "succeeds"), so a single top-level record would both hide partial
    failures and lose per-file snapshots. Each file gets its own before/after snapshot and
    its own operation_status.
    """
    paths = [p for p in (context.get("paths") or []) if isinstance(p, str) and p]
    before_map = {p: snapshot_path(p) for p in paths}

    try:
        result = func()
    except Exception:
        for p in paths:
            write_audit_record(build_audit_record(
                operation=operation, target_path=p, before=before_map.get(p),
                operation_status="error", error="tool exception",
            ))
        raise

    parsed = _parse_tool_result(result)
    items = parsed.get("results")
    if not isinstance(items, list) or not items:
        # A tool-level failure (e.g. validation) before any per-file work ran.
        write_audit_record(build_audit_record(
            operation=operation, target_path=paths or None,
            operation_status="error" if "error" in parsed else "success",
            error=parsed.get("error"),
        ))
        return result

    for item in items:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        item_error = item.get("error")
        item_status = "error" if item_error else "success"
        before = before_map.get(path) if isinstance(path, str) else None
        after = snapshot_path(path) if (item_status == "success" and isinstance(path, str)) else None
        write_audit_record(build_audit_record(
            operation=operation, target_path=path, before=before, after=after,
            operation_status=item_status, error=item_error,
        ))
    return result
