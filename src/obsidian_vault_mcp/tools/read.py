"""Read tools for the Obsidian vault MCP server."""

import json
import logging

import frontmatter

from ..vault import resolve_vault_path, read_file

def _normalize_fm(value):
    """Convert date/datetime objects to ISO strings for JSON serialization."""
    import datetime
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _normalize_fm(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_fm(v) for v in value]
    return value

logger = logging.getLogger(__name__)


def vault_read(path: str) -> str:
    """Read a file from the vault, returning content, metadata, and parsed frontmatter."""
    try:
        resolved = resolve_vault_path(path)
        content, metadata = read_file(path)

        fm_data = None
        try:
            post = frontmatter.loads(content)
            if post.metadata:
                fm_data = _normalize_fm(post.metadata)
        except Exception:
            pass

        return json.dumps({
            "path": path,
            "content": content,
            "metadata": metadata,
            "frontmatter": fm_data,
        })
    except ValueError as e:
        return json.dumps({"error": str(e), "path": path})
    except FileNotFoundError:
        return json.dumps({"error": f"File not found: {path}", "path": path})
    except Exception as e:
        logger.error(f"vault_read error for {path}: {e}")
        return json.dumps({"error": str(e), "path": path})


def vault_batch_read(paths: list[str], include_content: bool = True) -> str:
    """Read multiple files from the vault in one call."""
    results = []
    found = 0
    missing = 0

    for path in paths:
        try:
            content, metadata = read_file(path)

            fm_data = None
            try:
                post = frontmatter.loads(content)
                if post.metadata:
                    fm_data = _normalize_fm(post.metadata)
            except Exception:
                pass

            entry = {
                "path": path,
                "metadata": metadata,
                "frontmatter": fm_data,
            }
            if include_content:
                entry["content"] = content

            results.append(entry)
            found += 1
        except (ValueError, FileNotFoundError) as e:
            results.append({"path": path, "error": str(e)})
            missing += 1
        except Exception as e:
            results.append({"path": path, "error": str(e)})
            missing += 1

    return json.dumps({"files": results, "found": found, "missing": missing})
