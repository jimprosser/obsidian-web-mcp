"""Tests for the Obsidian Canvas tools (read / add node / add edge).

Covers the happy path, abuse inputs (path traversal, wrong extension, malformed
JSON, dangling edge references, schema violations) and the server wiring seam.
"""

import json

import pytest
from pydantic import ValidationError

from obsidian_vault_mcp import server
from obsidian_vault_mcp.models import VaultCanvasAddNodeInput, VaultCanvasAddEdgeInput
from obsidian_vault_mcp.tools.canvas import (
    vault_canvas_add_edge,
    vault_canvas_add_node,
    vault_canvas_read,
)


def _write_canvas(vault_dir, name, payload):
    (vault_dir / name).write_text(json.dumps(payload), encoding="utf-8")


# --- read ------------------------------------------------------------------


def test_canvas_read_parses_nodes_and_edges(vault_dir):
    _write_canvas(vault_dir, "board.canvas", {
        "nodes": [{"id": "n1", "type": "text", "x": 0, "y": 0, "width": 100, "height": 60, "text": "hi"}],
        "edges": [],
    })
    result = json.loads(vault_canvas_read("board.canvas"))
    assert "error" not in result
    assert result["nodes"][0]["id"] == "n1"
    assert result["nodes"][0]["text"] == "hi"
    assert result["edges"] == []


def test_canvas_read_missing_file_errors(vault_dir):
    result = json.loads(vault_canvas_read("nope.canvas"))
    assert "error" in result and "not found" in result["error"].lower()


def test_canvas_read_rejects_non_canvas_extension(vault_dir):
    result = json.loads(vault_canvas_read("test-note.md"))
    assert "error" in result and ".canvas" in result["error"]


def test_canvas_read_rejects_path_traversal(vault_dir):
    result = json.loads(vault_canvas_read("../escape.canvas"))
    assert "error" in result


def test_canvas_read_rejects_malformed_json(vault_dir):
    (vault_dir / "broken.canvas").write_text("{not json", encoding="utf-8")
    result = json.loads(vault_canvas_read("broken.canvas"))
    assert "error" in result and "JSON" in result["error"]


# --- add node --------------------------------------------------------------


def test_add_node_creates_file_and_generates_id(vault_dir):
    result = json.loads(vault_canvas_add_node(
        "new.canvas", {"type": "text", "x": 10, "y": 20, "width": 200, "height": 80, "text": "hello"}
    ))
    assert result["created"] is True
    assert (vault_dir / "new.canvas").exists()
    assert result["node"]["id"]  # generated
    # round-trips through read, extra field preserved
    read_back = json.loads(vault_canvas_read("new.canvas"))
    assert read_back["nodes"][0]["text"] == "hello"
    assert read_back["nodes"][0]["x"] == 10  # int preserved, not coerced to 10.0


def test_add_node_appends_to_existing(vault_dir):
    _write_canvas(vault_dir, "b.canvas", {"nodes": [{"id": "a1", "type": "text", "x": 0, "y": 0, "width": 50, "height": 50}], "edges": []})
    result = json.loads(vault_canvas_add_node("b.canvas", {"type": "group", "x": 1, "y": 1, "width": 300, "height": 300}))
    assert result["created"] is False
    assert len(result["nodes"]) == 2


def test_add_node_rejects_duplicate_id(vault_dir):
    _write_canvas(vault_dir, "c.canvas", {"nodes": [{"id": "dup", "type": "text", "x": 0, "y": 0, "width": 50, "height": 50}], "edges": []})
    result = json.loads(vault_canvas_add_node("c.canvas", {"id": "dup", "type": "text", "x": 5, "y": 5, "width": 50, "height": 50}))
    assert "error" in result and "already exists" in result["error"]


def test_add_node_invalid_schema_rejected_by_model(vault_dir):
    # missing required dimensions / non-positive width are rejected at validation
    with pytest.raises(ValidationError):
        VaultCanvasAddNodeInput(path="x.canvas", node={"type": "text", "x": 0, "y": 0})
    with pytest.raises(ValidationError):
        VaultCanvasAddNodeInput(path="x.canvas", node={"type": "text", "x": 0, "y": 0, "width": 0, "height": 10})
    with pytest.raises(ValidationError):
        VaultCanvasAddNodeInput(path="x.canvas", node={"id": "not alnum!", "type": "text", "x": 0, "y": 0, "width": 1, "height": 1})


# --- add edge --------------------------------------------------------------


def test_add_edge_appends_with_reference_check(vault_dir):
    _write_canvas(vault_dir, "g.canvas", {
        "nodes": [
            {"id": "n1", "type": "text", "x": 0, "y": 0, "width": 50, "height": 50},
            {"id": "n2", "type": "text", "x": 100, "y": 0, "width": 50, "height": 50},
        ],
        "edges": [],
    })
    result = json.loads(vault_canvas_add_edge(
        "g.canvas", {"fromNode": "n1", "fromSide": "right", "toNode": "n2", "toSide": "left"}
    ))
    assert "error" not in result
    assert len(result["edges"]) == 1
    assert result["edge"]["id"]  # generated


def test_add_edge_rejects_unknown_node_reference(vault_dir):
    _write_canvas(vault_dir, "h.canvas", {"nodes": [{"id": "n1", "type": "text", "x": 0, "y": 0, "width": 50, "height": 50}], "edges": []})
    result = json.loads(vault_canvas_add_edge(
        "h.canvas", {"fromNode": "n1", "fromSide": "right", "toNode": "ghost", "toSide": "left"}
    ))
    assert "error" in result and "existing canvas node ids" in result["error"]


def test_add_edge_requires_existing_file(vault_dir):
    result = json.loads(vault_canvas_add_edge(
        "missing.canvas", {"fromNode": "n1", "fromSide": "right", "toNode": "n2", "toSide": "left"}
    ))
    assert "error" in result and "not found" in result["error"].lower()


def test_add_edge_invalid_side_rejected_by_model(vault_dir):
    with pytest.raises(ValidationError):
        VaultCanvasAddEdgeInput(path="x.canvas", edge={"fromNode": "n1", "fromSide": "sideways", "toNode": "n2", "toSide": "left"})


# --- server wiring (the @mcp.tool seam, not just the helper) ---------------


def test_canvas_tools_registered_and_wired(vault_dir):
    # tools are registered on the FastMCP server
    for name in ("vault_canvas_read", "vault_canvas_add_node", "vault_canvas_add_edge"):
        assert server.mcp._tool_manager.get_tool(name) is not None
    # the server-level wrapper validates input and reaches the helper end to end
    result = json.loads(server.vault_canvas_add_node(
        "wired.canvas", {"type": "text", "x": 0, "y": 0, "width": 120, "height": 60, "text": "via wrapper"}
    ))
    assert result["created"] is True
    assert (vault_dir / "wired.canvas").exists()
