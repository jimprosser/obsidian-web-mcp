"""Write tools for the Obsidian vault MCP server."""

import base64
import binascii
import difflib
import logging
from pathlib import Path

import frontmatter

from .. import config, frontmatter_io
from ..frontmatter_io import YAMLError

from ..models import normalize_edit_aliases
from ..serialization import dumps
from ..vault import resolve_vault_path, read_file, write_bytes_atomic, write_file_atomic
from ..write_events import fire_write

logger = logging.getLogger(__name__)


def vault_write(
    path: str,
    content: str,
    create_dirs: bool = True,
    merge_frontmatter: bool = False,
    overwrite: bool = True,
) -> str:
    """Write a file to the vault, optionally merging frontmatter with existing content.

    overwrite=False makes it create-only: an existing file is left untouched and the
    call reports it, also when two calls race for the same name, so a client that
    lost a response can retry without replacing anything.
    """
    try:
        resolve_vault_path(path)

        if not overwrite and merge_frontmatter:
            # Merging needs an existing file; create-only forbids one. Refuse the
            # contradiction instead of silently ignoring one of the two.
            return dumps({
                "error": "merge_frontmatter needs an existing file and overwrite=false forbids one; use one or the other",
                "path": path,
                "created": False,
            })

        if merge_frontmatter:
            try:
                existing_content, _ = read_file(path)
                existing_meta, _ = frontmatter_io.loads(existing_content)
                new_meta, new_body = frontmatter_io.loads(content)

                # Mutate existing in place: untouched keys keep their original
                # formatting (quote style, comments, key order); new keys are
                # appended. ruamel round-trip avoids PyYAML's normalisation.
                for key, value in new_meta.items():
                    existing_meta[key] = value

                content = frontmatter_io.dumps(existing_meta, new_body)
            except FileNotFoundError:
                pass
            except YAMLError as e:
                # Malformed YAML in either side: abort rather than silently
                # dropping the existing frontmatter or nesting a stray --- block.
                # A correctable error beats a lossy write for an agent caller.
                return dumps({
                    "error": f"Frontmatter merge aborted: malformed YAML frontmatter ({e})",
                    "path": path,
                    "created": False,
                })

        try:
            is_new, size = write_file_atomic(path, content, create_dirs=create_dirs, overwrite=overwrite)
        except FileExistsError:
            return dumps({
                "error": f"File already exists: {path}. Set overwrite=true to replace it.",
                "path": path,
                "created": False,
            })

        fire_write("created" if is_new else "updated", [path])
        return dumps({"path": path, "created": is_new, "size": size})
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_write error for {path}: {e}")
        return dumps({"error": str(e), "path": path})


# Binary writes are restricted to an allowlist of media types, each mapped to the file
# extensions permitted for it. The map is deliberately conservative and lists only inert
# formats; the allowlist is the security boundary that keeps this from being an
# arbitrary-file-write. SVG is intentionally excluded: it can carry <script>/onload, and
# because validation is by declared media_type + extension (never by sniffing bytes),
# allowing it would be an arbitrary-active-content write into a vault that may be synced or
# rendered in a preview surface.
DEFAULT_ALLOWED_BINARY_MEDIA_TYPES = {
    "image/png": {".png"},
    "image/jpeg": {".jpg", ".jpeg"},
    "image/webp": {".webp"},
    "image/gif": {".gif"},
    "application/pdf": {".pdf"},
}


def allowed_binary_media_types() -> dict[str, set[str]]:
    """The built-in allowlist plus the operator's VAULT_EXTRA_BINARY_MEDIA_TYPES_JSON.

    Extras are added per media type and never remove a built-in entry, so no setting can
    drop PNG or PDF.
    """
    merged = {media_type: set(extensions) for media_type, extensions in DEFAULT_ALLOWED_BINARY_MEDIA_TYPES.items()}
    for media_type, extensions in config.EXTRA_BINARY_MEDIA_TYPES.items():
        merged.setdefault(media_type, set()).update(extensions)
    return merged


def _validate_binary_target(path: str, media_type: str) -> Path:
    """Resolve a binary target path and enforce the media-type / extension allowlist."""
    resolved = resolve_vault_path(path)
    allowed_extensions = allowed_binary_media_types().get(media_type.strip().lower())
    if not allowed_extensions:
        raise ValueError(f"Unsupported media_type: {media_type}")
    extension = Path(path).suffix.lower()
    if extension not in allowed_extensions:
        raise ValueError(f"Extension '{extension}' is not allowed for media_type '{media_type}'")
    return resolved


def _decode_base64(data: str) -> bytes:
    """Decode a strict base64 payload."""
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64 data") from exc


def vault_write_binary(
    path: str,
    data: str,
    media_type: str,
    overwrite: bool = False,
    create_dirs: bool = True,
) -> str:
    """Write an allowed binary file (image/PDF) to the vault from base64-encoded content.

    The allowlist gates on the declared ``media_type`` and the file extension, not on the
    bytes -- a caller can write arbitrary bytes under an allowed extension. That is
    acceptable for a single-user vault (you only fool yourself), but the type is a
    convention, not a guarantee. PDF in particular can carry active content; it is included
    because it is a core attachment format, not because it is inert.
    """
    try:
        resolved = _validate_binary_target(path, media_type)

        try:
            decoded = _decode_base64(data)
        except ValueError as exc:
            return dumps({"error": str(exc), "path": path, "media_type": media_type})

        if resolved.exists() and not overwrite:
            return dumps({
                "error": f"File already exists: {path}. Set overwrite=true to replace it.",
                "path": path,
                "media_type": media_type,
            })

        is_new, size = write_bytes_atomic(path, decoded, create_dirs=create_dirs, overwrite=overwrite)

        fire_write("created" if is_new else "updated", [path])
        return dumps({"path": path, "created": is_new, "size": size, "media_type": media_type})
    except ValueError as e:
        return dumps({"error": str(e), "path": path, "media_type": media_type})
    except Exception as e:
        logger.error(f"vault_write_binary error for {path}: {e}")
        return dumps({"error": str(e), "path": path, "media_type": media_type})


def _unified_diff(path: str, before: str, after: str) -> str:
    """Return a compact unified diff for an edit preview or result."""
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"{path} before",
        tofile=f"{path} after",
        lineterm="",
    ))


# A near-miss hint is only emitted when the closest line shares at least this
# fraction of old_text. Below it the "hint" is noise (unrelated input, blank
# lines) and would mislead more than help.
_NEAR_MISS_MIN_SIMILARITY = 0.5

# A near-miss is a typo-scale hint, so an old_text larger than this is never a
# plausible single-line match. It is also the input that pinned the CPU: the
# per-line SequenceMatcher over a ~1 MB high-entropy old_text on a zero-match
# edit did not return in minutes (an authenticated DoS, since old_text is bounded
# only by the per-edit size limit). Skip the scan above this size.
_NEAR_MISS_MAX_OLD_TEXT = 1024

# The per-line SequenceMatcher cost grows with len(old_text) * len(line), so even
# a capped old_text (e.g. 1 KB) against a large many-line file still pins the CPU
# (~15 s for a 1 MB / 25k-line file, and the edited file's size is not otherwise
# bounded). Stop scanning once the cumulative work crosses this budget; the
# near-miss is a best-effort hint, so a partial scan is an acceptable trade for
# the safety. len(old_text)*len(line) is an order-of-magnitude proxy, not exact
# (difflib's constant factor is worse for low-alphabet, autojunk-disabled lines),
# so the budget is sized to keep even an adversarial file under ~1 s, well below
# the per-edit timeout. Typo-scale old_text (small) still scans thousands of
# lines, so normal notes are covered in full.
_NEAR_MISS_WORK_BUDGET = 10_000_000


def _normalize_edit_aliases(edit: dict) -> tuple[dict | None, str | None]:
    """Apply the shared alias normalization, returning (normalized, error).

    This guards the direct-dict callers of vault_edit (tests, internal use).
    The MCP path is already canonicalized: server.py validates each edit as a
    VaultEditOperationInput and passes model_dump() output, so this is a no-op
    there rather than dead code.
    """
    try:
        return normalize_edit_aliases(edit), None
    except ValueError as exc:
        return None, str(exc)


def _find_near_miss(content: str, old_text: str) -> dict | None:
    """Return the document line closest to old_text for a zero-match edit.

    Line-scoped: one SequenceMatcher pass per line, so work grows with file
    size rather than quadratically across lines (for a fixed old_text). The
    similarity is the fraction of old_text matched on the closest line, which
    separates a one-character typo (high) from text that is simply absent
    (low). Returns None when the best line is below the similarity floor, so
    unrelated input produces no misleading hint, and skips the scan entirely
    for an old_text larger than _NEAR_MISS_MAX_OLD_TEXT (not a plausible
    single-line near-miss, and the input that made the scan a CPU DoS). A
    cumulative work budget (_NEAR_MISS_WORK_BUDGET) bounds the scan on very
    large files, so the hint is best-effort there rather than unbounded.
    """
    if not old_text or len(old_text) > _NEAR_MISS_MAX_OLD_TEXT:
        return None

    lines = content.splitlines()
    if not lines:
        return None

    matcher = difflib.SequenceMatcher(a=old_text)
    best_similarity, best_index = 0.0, 0
    budget = _NEAR_MISS_WORK_BUDGET
    for index, line in enumerate(lines):
        budget -= len(old_text) * (len(line) + 1)
        if budget < 0:
            # Cumulative work budget spent (huge file / very many lines): stop
            # scanning and report the best line found so far rather than pin CPU.
            break
        matcher.set_seq2(line)
        matched = sum(block.size for block in matcher.get_matching_blocks())
        similarity = matched / len(old_text)
        if similarity > best_similarity:
            best_similarity, best_index = similarity, index

    if best_similarity < _NEAR_MISS_MIN_SIMILARITY:
        return None

    return {
        "line_number": best_index + 1,
        "line": lines[best_index],
        "similarity": round(best_similarity, 2),
    }


def _dry_run_report(path: str, original_content: str, normalized_edits: list[dict]) -> str:
    """Preview edits without writing, simulating the sequential apply.

    Each old_text is counted against the running document the preceding edits
    would have produced (not the original), so the preview predicts the
    in-order apply exactly: a chained set whose first edit's new_text feeds or
    duplicates a later edit's old_text is reported as it will actually apply.

    Unlike the apply path this does not fail fast: every edit's match count
    (0, 1, or many) is reported so one response surfaces all mismatches. An
    edit that does not match exactly once is left unapplied in the simulation
    and flips the result to not-applicable. When every edit matches exactly
    once the running document is the applied result, so its diff is included.
    """
    match_counts = []
    all_unique = True
    preview = original_content
    replacements = 0
    for index, edit in enumerate(normalized_edits):
        old_text = edit.get("old_text", "")
        replace_all = bool(edit.get("replace_all", False))
        entry = {"index": index}
        if replace_all:
            entry["replace_all"] = True
        if not old_text:
            entry["count"] = 0
            entry["error"] = "no old_text to match"
            all_unique = False
            match_counts.append(entry)
            continue
        count = preview.count(old_text)
        entry["count"] = count
        if count == 0:
            near_miss = _find_near_miss(preview, old_text)
            if near_miss:
                entry["near_miss"] = near_miss
        if count == 0 or (count != 1 and not replace_all):
            all_unique = False
            match_counts.append(entry)
            continue
        # Applicable: fold it into the running document so the next edit is
        # validated against the same state the real apply would see. With
        # replace_all every occurrence goes in this step, exactly as it would
        # when applied.
        preview = (
            preview.replace(old_text, edit.get("new_text", ""))
            if replace_all
            else preview.replace(old_text, edit.get("new_text", ""), 1)
        )
        replacements += count if replace_all else 1
        match_counts.append(entry)

    size_error = None
    if all_unique:
        diff = _unified_diff(path, original_content, preview)
        size = len(preview.encode("utf-8"))
        if size > config.MAX_CONTENT_SIZE:
            # write_file_atomic refuses content over MAX_CONTENT_SIZE, so the real
            # apply would fail. Predict that rather than preview an unlandable write.
            size_error = (
                f"Resulting content size {size} bytes exceeds limit of "
                f"{config.MAX_CONTENT_SIZE} bytes; apply would fail"
            )
            diff = ""
            all_unique = False
    else:
        diff = ""
        size = len(original_content.encode("utf-8"))

    report = {
        "path": path,
        "changed": False,
        "dry_run": True,
        "diff": diff,
        "match_counts": match_counts,
        "edits_applied": len(normalized_edits) if all_unique else 0,
        "replacements": replacements if all_unique else 0,
        "size": size,
    }
    if size_error:
        report["error"] = size_error
    return dumps(report)


def vault_edit(path: str, edits: list[dict], dry_run: bool = False) -> str:
    """Apply exact text replacements to an existing file without resending the full body."""
    try:
        content, _ = read_file(path)
        original_content = content

        # Normalize aliases up front; an alias conflict fails fast in either mode.
        normalized_edits = []
        for index, edit in enumerate(edits):
            normalized_edit, alias_error = _normalize_edit_aliases(edit)
            if alias_error:
                return dumps({
                    "error": f"Edit {index}: {alias_error}",
                    "path": path,
                    "changed": False,
                    "dry_run": dry_run,
                    "diff": "",
                    "edits_applied": 0,
                    "size": len(original_content.encode("utf-8")),
                })
            normalized_edits.append(normalized_edit)

        if dry_run:
            return _dry_run_report(path, original_content, normalized_edits)

        replacements = 0
        for index, normalized_edit in enumerate(normalized_edits):
            old_text = normalized_edit.get("old_text", "")
            new_text = normalized_edit.get("new_text", "")
            replace_all = bool(normalized_edit.get("replace_all", False))

            if not old_text:
                # An empty old_text would make content.count() report a phantom
                # match for every position; reject it as the malformed edit it is.
                return dumps({
                    "error": f"Edit {index} has no old_text to match",
                    "path": path,
                    "changed": False,
                    "dry_run": dry_run,
                    "diff": "",
                    "edits_applied": 0,
                    "size": len(original_content.encode("utf-8")),
                })

            count = content.count(old_text)

            if count == 0 or (count != 1 and not replace_all):
                requirement = "at least once" if replace_all else "exactly once"
                payload = {
                    "error": (
                        f"Edit {index} old_text must match {requirement}; "
                        f"found {count} matches"
                    ),
                    "path": path,
                    "changed": False,
                    "dry_run": dry_run,
                    "diff": "",
                    "edits_applied": 0,
                    "size": len(original_content.encode("utf-8")),
                }
                if count == 0:
                    near_miss = _find_near_miss(content, old_text)
                    if near_miss:
                        payload["near_miss"] = near_miss
                return dumps(payload)

            content = content.replace(old_text, new_text) if replace_all else content.replace(old_text, new_text, 1)
            replacements += count if replace_all else 1

        diff = _unified_diff(path, original_content, content)
        size = len(content.encode("utf-8"))

        changed = content != original_content
        if changed:
            write_file_atomic(path, content, create_dirs=False)
            fire_write("updated", [path])

        return dumps({
            "path": path,
            "changed": changed,
            "dry_run": False,
            "diff": diff,
            "edits_applied": len(edits),
            "replacements": replacements,
            "size": size,
        })
    except ValueError as e:
        return dumps({
            "error": str(e),
            "path": path,
            "changed": False,
            "dry_run": dry_run,
            "diff": "",
            "edits_applied": 0,
            "size": 0,
        })
    except FileNotFoundError:
        return dumps({
            "error": f"File not found: {path}",
            "path": path,
            "changed": False,
            "dry_run": dry_run,
            "diff": "",
            "edits_applied": 0,
            "size": 0,
        })
    except Exception as e:
        logger.error(f"vault_edit error for {path}: {e}")
        return dumps({
            "error": str(e),
            "path": path,
            "changed": False,
            "dry_run": dry_run,
            "diff": "",
            "edits_applied": 0,
            "size": 0,
        })


def vault_append(
    path: str,
    content: str,
    separator: str = "\n\n",
    create_dirs: bool = True,
) -> str:
    """Append content to a file without requiring the caller to send the full body."""
    try:
        resolve_vault_path(path)

        created = False
        try:
            existing_content, _ = read_file(path)
        except FileNotFoundError:
            existing_content = ""
            created = True

        if created or not existing_content:
            new_content = content
        elif content:
            new_content = f"{existing_content}{separator}{content}"
        else:
            new_content = existing_content

        changed = new_content != existing_content
        if changed:
            _, size = write_file_atomic(path, new_content, create_dirs=create_dirs)
            fire_write("created" if created else "updated", [path])
        else:
            size = len(existing_content.encode("utf-8"))

        return dumps({
            "path": path,
            "changed": changed,
            "created": created,
            "appended": not created and changed,
            "size": size,
        })
    except ValueError as e:
        return dumps({
            "error": str(e),
            "path": path,
            "changed": False,
            "created": False,
            "appended": False,
            "size": 0,
        })
    except Exception as e:
        logger.error(f"vault_append error for {path}: {e}")
        return dumps({
            "error": str(e),
            "path": path,
            "changed": False,
            "created": False,
            "appended": False,
            "size": 0,
        })


def vault_batch_frontmatter_update(updates: list[dict]) -> str:
    """Update frontmatter fields on multiple files without changing body content."""
    results = []

    for update in updates:
        file_path = update.get("path", "")
        fields = update.get("fields", {})

        try:
            content, _ = read_file(file_path)
            post = frontmatter.loads(content)

            for key, value in fields.items():
                post.metadata[key] = value

            new_content = frontmatter.dumps(post)
            write_file_atomic(file_path, new_content, create_dirs=False)

            results.append({"path": file_path, "updated": True})
        except FileNotFoundError:
            results.append({"path": file_path, "updated": False, "error": "File not found"})
        except ValueError as e:
            results.append({"path": file_path, "updated": False, "error": str(e)})
        except Exception as e:
            results.append({"path": file_path, "updated": False, "error": str(e)})

    # One event per batch, carrying only the paths actually written.
    written = [r["path"] for r in results if r.get("updated")]
    if written:
        fire_write("updated", written)

    return dumps({"results": results})
