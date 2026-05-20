"""JSON serialization helpers for vault MCP tools.

PyYAML / python-frontmatter auto-convert unquoted YAML dates
(e.g. `created: 2026-05-18`) to datetime.date objects, which json.dumps
cannot serialize by default. This helper converts date/datetime/time
objects to ISO 8601 strings so vault_read and friends return proper JSON.
"""
import json
from datetime import date, datetime, time


def _default(obj):
    """Convert non-JSON-serializable types to JSON-safe representations."""
    if isinstance(obj, (date, datetime, time)):
        return obj.isoformat()
    raise TypeError(
        f"Object of type {type(obj).__name__} is not JSON serializable"
    )


def dumps(data) -> str:
    """json.dumps that handles datetime.date / datetime / time objects."""
    return json.dumps(data, default=_default)
