"""Canvas tools for the Obsidian vault MCP server.

Read and append to Obsidian ``.canvas`` files. These are pure-filesystem JSON
operations: no plugin, no network, no subprocess, no new config. Writes go
through the atomic write path so Obsidian Sync never sees a partial file, and
unknown node/edge fields are preserved so round-tripping a canvas is lossless.
"""

import json
import logging
import secrets
import string

from ..serialization import dumps
from ..vault import read_file, resolve_vault_path, write_file_atomic

logger = logging.getLogger(__name__)

_CANVAS_ID_ALPHABET = string.ascii_letters + string.digits
_CANVAS_ID_LENGTH = 16


def _require_canvas_path(path: str) -> None:
    """Validate the vault path and enforce the ``.canvas`` extension.

    ``resolve_vault_path`` raises ValueError on traversal, dotfiles, or null
    bytes; we re-use it so canvas paths get the same guard as every other tool.
    """
    resolve_vault_path(path)
    if not path.lower().endswith(".canvas"):
        raise ValueError("Canvas path must end with .canvas")


def _load_canvas(path: str, *, must_exist: bool) -> dict:
    """Load and structurally validate a ``.canvas`` JSON document."""
    _require_canvas_path(path)
    try:
        content, _ = read_file(path)
    except FileNotFoundError:
        if must_exist:
            raise ValueError(f"Canvas file not found: {path}") from None
        return {"nodes": [], "edges": []}

    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid Canvas JSON: {exc.msg}") from exc

    if not isinstance(payload, dict):
        raise ValueError("Canvas file must contain a JSON object")
    nodes = payload.get("nodes", [])
    edges = payload.get("edges", [])
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("Canvas file must contain 'nodes' and 'edges' arrays")
    if not all(isinstance(item, dict) for item in nodes):
        raise ValueError("Canvas nodes must be JSON objects")
    if not all(isinstance(item, dict) for item in edges):
        raise ValueError("Canvas edges must be JSON objects")
    payload["nodes"] = nodes
    payload["edges"] = edges
    return payload


def _existing_ids(items: list[dict]) -> set:
    return {item["id"] for item in items if isinstance(item.get("id"), str)}


def _generate_id(taken: set) -> str:
    while True:
        candidate = "".join(secrets.choice(_CANVAS_ID_ALPHABET) for _ in range(_CANVAS_ID_LENGTH))
        if candidate not in taken:
            return candidate


def _canvas_body(canvas: dict) -> str:
    """Serialize the canvas back to disk as indented JSON (Obsidian's format)."""
    return json.dumps(canvas, ensure_ascii=False, indent=2) + "\n"


def vault_canvas_read(path: str) -> str:
    """Read and parse an Obsidian ``.canvas`` file."""
    try:
        canvas = _load_canvas(path, must_exist=True)
        return dumps({"path": path, "nodes": canvas["nodes"], "edges": canvas["edges"]})
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_canvas_read error for {path}: {e}")
        return dumps({"error": str(e), "path": path})


def vault_canvas_add_node(path: str, node: dict) -> str:
    """Append a node to a ``.canvas`` file, creating the file when it is missing."""
    try:
        canvas = _load_canvas(path, must_exist=False)
        node = dict(node)
        taken = _existing_ids(canvas["nodes"]) | _existing_ids(canvas["edges"])
        node_id = node.get("id")
        if node_id is None:
            node["id"] = _generate_id(taken)
        elif node_id in taken:
            return dumps({"error": f"Node id already exists: {node_id}", "path": path})

        canvas["nodes"].append(node)
        is_new, size = write_file_atomic(path, _canvas_body(canvas), create_dirs=True)
        return dumps({
            "path": path,
            "created": is_new,
            "size": size,
            "node": node,
            "nodes": canvas["nodes"],
            "edges": canvas["edges"],
        })
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_canvas_add_node error for {path}: {e}")
        return dumps({"error": str(e), "path": path})


def vault_canvas_add_edge(path: str, edge: dict) -> str:
    """Append an edge to an existing ``.canvas`` file."""
    try:
        canvas = _load_canvas(path, must_exist=True)
        edge = dict(edge)
        node_ids = _existing_ids(canvas["nodes"])
        if edge["fromNode"] not in node_ids or edge["toNode"] not in node_ids:
            return dumps({
                "error": "fromNode and toNode must reference existing canvas node ids",
                "path": path,
            })

        taken = node_ids | _existing_ids(canvas["edges"])
        edge_id = edge.get("id")
        if edge_id is None:
            edge["id"] = _generate_id(taken)
        elif edge_id in taken:
            return dumps({"error": f"Edge id already exists: {edge_id}", "path": path})

        canvas["edges"].append(edge)
        is_new, size = write_file_atomic(path, _canvas_body(canvas), create_dirs=True)
        return dumps({
            "path": path,
            "created": is_new,
            "size": size,
            "edge": edge,
            "nodes": canvas["nodes"],
            "edges": canvas["edges"],
        })
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_canvas_add_edge error for {path}: {e}")
        return dumps({"error": str(e), "path": path})
