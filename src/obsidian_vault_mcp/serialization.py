"""JSON serialization helpers for the Obsidian vault MCP server.

python-frontmatter parses YAML date fields into Python date/datetime objects,
which the stdlib json encoder can't handle. This module provides a drop-in
replacement for json.dumps that serializes those types as ISO 8601 strings (#5).

It is also the single place that controls how each tool serializes its result
payload, so all tool modules should route through dumps() rather than calling
json.dumps directly. Two defaults make responses token-efficient:

- ensure_ascii=False: non-ASCII text (Korean, Japanese, emoji, etc.) is emitted
  verbatim as UTF-8 instead of \\uXXXX escapes. The default True roughly doubled
  the size of a CJK-heavy response (and up to tripled it for non-BMP emoji, which
  escape to 12-character surrogate pairs), and produced escaped paths that could
  fail to round-trip. The decoded object is identical either way; ASCII-only
  responses are unaffected.
- compact separators: drops the spaces after ',' and ':' that json.dumps inserts
  by default. Responses are consumed by a model, not read raw, so that whitespace
  is pure overhead.

Callers may override either default by passing the keyword explicitly.
"""

import json
import logging
from datetime import date, datetime

logger = logging.getLogger(__name__)


class _VaultEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


def dumps(obj, **kwargs) -> str:
    """json.dumps with date/datetime support and token-efficient defaults."""
    kwargs.setdefault("ensure_ascii", False)
    kwargs.setdefault("separators", (",", ":"))
    result = json.dumps(obj, cls=_VaultEncoder, **kwargs)
    if not kwargs["ensure_ascii"]:
        # A filename that is not valid UTF-8 reaches us as a lone surrogate
        # (os.fsdecode uses surrogateescape). json.dumps accepts it, but the
        # resulting string then raises UnicodeEncodeError when the transport
        # encodes it to UTF-8 -- outside any tool's error handling. Fall back to
        # escaped output so one odd filename cannot crash an otherwise fine
        # response.
        try:
            result.encode("utf-8")
        except UnicodeEncodeError:
            logger.warning(
                "Response contains a non-UTF-8 (surrogate) string, likely from a "
                "filename that is not valid UTF-8; falling back to escaped output"
            )
            result = json.dumps(obj, cls=_VaultEncoder, **{**kwargs, "ensure_ascii": True})
    return result
