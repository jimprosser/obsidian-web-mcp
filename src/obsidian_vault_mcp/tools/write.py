"""Write tools for the Obsidian vault MCP server."""

import json
import logging
import re

import frontmatter

from ..vault import resolve_vault_path, read_file, write_file_atomic

logger = logging.getLogger(__name__)


# Matches Markdown task checkboxes: `- [ ]`, `* [x]`, `+ [X]`, etc.
# Task Forge (Obsidian plugin used in this vault) converts ALL such lines into
# tracked tasks. Block writes that contain them unless the caller explicitly
# opts in via allow_checkboxes=True.
_CHECKBOX_PATTERN = re.compile(r'^\s*[-*+]\s*\[[ xX]\]', re.MULTILINE)

# Strip fenced code blocks before checking — Task Forge respects markdown
# structure and ignores ``` fenced regions.
# TODO: extend to inline-code (`...`) if false positives appear in practice.
_FENCED_BLOCK_PATTERN = re.compile(r'```.*?```', re.DOTALL)


def _content_has_checkbox(content: str) -> bool:
    """True if `content` contains a Markdown checkbox outside fenced code blocks."""
    stripped = _FENCED_BLOCK_PATTERN.sub('', content)
    return bool(_CHECKBOX_PATTERN.search(stripped))


def vault_write(
    path: str,
    content: str,
    create_dirs: bool = True,
    merge_frontmatter: bool = False,
    allow_checkboxes: bool = False,
) -> str:
    """Write a file to the vault, optionally merging frontmatter with existing content."""
    try:
        resolve_vault_path(path)

        if not allow_checkboxes and _content_has_checkbox(content):
            return json.dumps({
                "error": (
                    "Checkboxes detected in content but allow_checkboxes=False.\n"
                    "Task Forge will pick these up as tasks automatically.\n"
                    "If you intend to create tasks: set allow_checkboxes=True\n"
                    "If this is a regular note: use plain bullets (- item) or "
                    "numbered lists (1. item) instead."
                ),
                "path": path,
            })

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

        return json.dumps({"path": path, "created": is_new, "size": size})
    except ValueError as e:
        return json.dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_write error for {path}: {e}")
        return json.dumps({"error": str(e), "path": path})


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

    return json.dumps({"results": results})
