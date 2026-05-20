"""Management tools for the Obsidian vault MCP server."""

from ..json_utils import dumps as json_dumps
import logging

from ..vault import list_directory, move_path, delete_path, resolve_vault_path

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
        return json_dumps({"items": items, "total": len(items)})
    except ValueError as e:
        return json_dumps({"error": str(e)})
    except FileNotFoundError:
        return json_dumps({"error": f"Directory not found: {path}"})
    except Exception as e:
        logger.error(f"vault_list error: {e}")
        return json_dumps({"error": str(e)})


def vault_move(source: str, destination: str, create_dirs: bool = True) -> str:
    """Move a file or directory within the vault."""
    try:
        moved = move_path(source, destination, create_dirs=create_dirs)
        return json_dumps({"source": source, "destination": destination, "moved": moved})
    except ValueError as e:
        return json_dumps({"error": str(e), "source": source, "destination": destination})
    except Exception as e:
        logger.error(f"vault_move error: {e}")
        return json_dumps({"error": str(e), "source": source, "destination": destination})


def vault_delete(path: str, confirm: bool = False) -> str:
    """Delete a file by moving it to .trash/ in the vault."""
    if not confirm:
        return json_dumps({
            "error": "Set confirm=true to execute deletion. Files are moved to .trash/, not hard deleted.",
            "path": path,
        })

    try:
        deleted = delete_path(path)
        return json_dumps({"path": path, "deleted": deleted})
    except ValueError as e:
        return json_dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_delete error: {e}")
        return json_dumps({"error": str(e), "path": path})
