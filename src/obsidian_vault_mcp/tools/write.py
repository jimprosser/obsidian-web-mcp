"""Write tools for the Obsidian vault MCP server."""

import base64
import binascii
import difflib
import logging
from pathlib import Path

import frontmatter

from .. import frontmatter_io
from ..frontmatter_io import YAMLError
from ..serialization import dumps
from ..vault import resolve_vault_path, read_file, write_bytes_atomic, write_file_atomic
from ..write_events import fire_write

logger = logging.getLogger(__name__)


def vault_write(path: str, content: str, create_dirs: bool = True, merge_frontmatter: bool = False) -> str:
    """Write a file to the vault, optionally merging frontmatter with existing content."""
    try:
        resolve_vault_path(path)

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

        is_new, size = write_file_atomic(path, content, create_dirs=create_dirs)

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


def _validate_binary_target(path: str, media_type: str) -> Path:
    """Resolve a binary target path and enforce the media-type / extension allowlist."""
    resolved = resolve_vault_path(path)
    allowed_extensions = DEFAULT_ALLOWED_BINARY_MEDIA_TYPES.get(media_type.strip().lower())
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


def _normalize_edit_aliases(edit: dict) -> tuple[dict | None, str | None]:
    normalized = dict(edit)
    for canonical, alias in (("old_text", "old_str"), ("new_text", "new_str")):
        if canonical in normalized and alias in normalized:
            return None, f"Use either '{canonical}' or '{alias}', not both"
        if alias in normalized:
            normalized[canonical] = normalized.pop(alias)

    return normalized, None


def vault_edit(path: str, edits: list[dict], dry_run: bool = False) -> str:
    """Apply exact text replacements to an existing file without resending the full body."""
    try:
        content, _ = read_file(path)
        original_content = content

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

            old_text = normalized_edit.get("old_text", "")
            new_text = normalized_edit.get("new_text", "")
            count = content.count(old_text)

            if count != 1:
                return dumps({
                    "error": (
                        f"Edit {index} old_text must match exactly once; "
                        f"found {count} matches"
                    ),
                    "path": path,
                    "changed": False,
                    "dry_run": dry_run,
                    "diff": "",
                    "edits_applied": 0,
                    "size": len(original_content.encode("utf-8")),
                })

            content = content.replace(old_text, new_text, 1)

        diff = _unified_diff(path, original_content, content)
        size = len(content.encode("utf-8"))

        if dry_run:
            return dumps({
                "path": path,
                "changed": False,
                "dry_run": True,
                "diff": diff,
                "edits_applied": len(edits),
                "size": size,
            })

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
