"""Write tools for the Obsidian vault MCP server."""

import difflib
import logging

import frontmatter

from ..serialization import dumps
from ..vault import resolve_vault_path, read_file, write_file_atomic

logger = logging.getLogger(__name__)


def vault_write(path: str, content: str, create_dirs: bool = True, merge_frontmatter: bool = False) -> str:
    """Write a file to the vault, optionally merging frontmatter with existing content."""
    try:
        resolve_vault_path(path)

        if merge_frontmatter:
            try:
                existing_content, _ = read_file(path)
                existing_post = frontmatter.loads(existing_content)
                new_post = frontmatter.loads(content)

                merged_meta = dict(existing_post.metadata)
                merged_meta.update(new_post.metadata)

                new_post.metadata = merged_meta
                content = frontmatter.dumps(new_post)
            except FileNotFoundError:
                pass
            except Exception as e:
                logger.warning(f"Frontmatter merge failed for {path}, writing as-is: {e}")

        is_new, size = write_file_atomic(path, content, create_dirs=create_dirs)

        return dumps({"path": path, "created": is_new, "size": size})
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_write error for {path}: {e}")
        return dumps({"error": str(e), "path": path})


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

    return dumps({"results": results})
