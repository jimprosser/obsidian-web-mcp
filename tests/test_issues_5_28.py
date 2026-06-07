"""Tests for #5 (date JSON serialization) and #28 (index built once, not per request)."""

import json
from datetime import date, datetime

from obsidian_vault_mcp.serialization import dumps
from obsidian_vault_mcp.tools.read import vault_read


# --- #5: bare YAML dates must serialize -----------------------------------------

def test_dumps_serializes_date_and_datetime():
    out = dumps({"created": date(2026, 4, 5), "ts": datetime(2026, 4, 5, 12, 30, 0)})
    parsed = json.loads(out)
    assert parsed["created"] == "2026-04-05"
    assert parsed["ts"].startswith("2026-04-05T12:30")


def test_vault_read_handles_bare_yaml_date(vault_dir):
    """A file with an unquoted frontmatter date reads without error (#5)."""
    (vault_dir / "dated.md").write_text(
        "---\ncreated: 2026-04-05\ntags: [test]\n---\n\nBody.\n"
    )
    result = json.loads(vault_read("dated.md"))
    assert "error" not in result, result
    assert result["frontmatter"]["created"] == "2026-04-05"


# --- #28: the index is built once and start() is idempotent ---------------------

def test_frontmatter_index_start_is_idempotent(vault_dir):
    """A second start() while already running is a no-op (index is process-scoped,
    not rebuilt per request)."""
    from obsidian_vault_mcp.frontmatter_index import FrontmatterIndex
    idx = FrontmatterIndex()
    try:
        idx.start()
        first_observer = idx._observer
        idx.start()  # must NOT spawn a second observer or re-walk
        assert idx._observer is first_observer
    finally:
        idx.stop()
