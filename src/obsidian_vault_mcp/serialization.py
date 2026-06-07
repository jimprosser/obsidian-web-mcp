"""JSON serialization helpers for the Obsidian vault MCP server.

python-frontmatter parses YAML date fields into Python date/datetime objects,
which the stdlib json encoder can't handle. This module provides a drop-in
replacement for json.dumps that serializes those types as ISO 8601 strings (#5).
"""

import json
from datetime import date, datetime


class _VaultEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


def dumps(obj, **kwargs) -> str:
    """json.dumps with automatic date/datetime serialization."""
    return json.dumps(obj, cls=_VaultEncoder, **kwargs)
