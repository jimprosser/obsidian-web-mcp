"""Management tools for the Obsidian vault MCP server."""

import logging

from ..links import update_links_for_move
from ..serialization import dumps
from ..vault import list_directory, move_path, delete_path
from ..write_events import fire_write

logger = logging.getLogger(__name__)


def vault_list(
    path: str = "",
    depth: int = 1,
    include_files: bool = True,
    include_dirs: bool = True,
    pattern: str | None = None,
) -> str:
    """List directory contents in the vault."""
    try:
        items = list_directory(
            path,
            depth=depth,
            include_files=include_files,
            include_dirs=include_dirs,
            pattern=pattern,
        )
        return dumps({"items": items, "total": len(items)})
    except ValueError as e:
        return dumps({"error": str(e)})
    except FileNotFoundError:
        return dumps({"error": f"Directory not found: {path}"})
    except Exception as e:
        logger.error(f"vault_list error: {e}")
        return dumps({"error": str(e)})


def vault_move(source: str, destination: str, create_dirs: bool = True) -> str:
    """Move or rename a file or directory within the vault.

    Every reference to the moved note is repointed afterwards, the way Obsidian
    does on a rename: a link that followed the note before the move follows it
    after. The rewrite runs after the move and never undoes it, so if it fails
    the summary says so and the move still stands.
    """
    try:
        moved = move_path(source, destination, create_dirs=create_dirs)
        if moved:
            fire_write("moved", [source, destination])
        result = {"source": source, "destination": destination, "moved": moved}

        if moved:
            summary = update_links_for_move(source, destination)
            result["links"] = summary
            if summary["files_updated"]:
                fire_write("updated", summary["files"])
        return dumps(result)
    except ValueError as e:
        return dumps({"error": str(e), "source": source, "destination": destination})
    except Exception as e:
        logger.error(f"vault_move error: {e}")
        return dumps({"error": str(e), "source": source, "destination": destination})


def vault_delete(path: str, confirm: bool = False) -> str:
    """Delete a file by moving it to .trash/ in the vault."""
    if not confirm:
        return dumps({
            "error": "Set confirm=true to execute deletion. Files are moved to .trash/, not hard deleted.",
            "path": path,
        })

    try:
        deleted = delete_path(path)
        if deleted:
            fire_write("deleted", [path])
        return dumps({"path": path, "deleted": deleted})
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_delete error: {e}")
        return dumps({"error": str(e), "path": path})
