"""YAML frontmatter I/O that preserves formatting across round-trips.

Uses ruamel.yaml in round-trip mode so quote style, comments, block/flow
style, boolean forms (yes/no vs true/false), and key order survive a
load-then-dump cycle. PyYAML (via python-frontmatter) normalizes all of
these, which rewrites users' carefully-formatted frontmatter on every
update.
"""

from __future__ import annotations

import io
import logging
import re

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

logger = logging.getLogger(__name__)

_FRONTMATTER_RE = re.compile(
    r"\A---[ \t]*\r?\n(.*?)(?:\r?\n)?---[ \t]*\r?\n?(.*)\Z",
    re.DOTALL,
)


_YAML = YAML(typ="rt")
_YAML.preserve_quotes = True
_YAML.width = 4096
_YAML.indent(mapping=2, sequence=4, offset=2)


def loads(content: str) -> tuple[dict, str]:
    """Parse a markdown file into (metadata, body).

    When frontmatter is present, metadata is a ruamel.yaml CommentedMap that
    retains the original formatting for round-trip dumping. When absent,
    returns ({}, content).
    """
    match = _FRONTMATTER_RE.match(content)
    if match is None:
        return {}, content

    raw_yaml, body = match.group(1), match.group(2)

    if raw_yaml.strip() == "":
        return {}, body

    # Ensure the YAML text ends with a newline so ruamel correctly parses
    # trailing-newline chomping on literal/folded block scalars at EOF.
    if not raw_yaml.endswith("\n"):
        raw_yaml += "\n"

    try:
        metadata = _YAML.load(raw_yaml)
    except YAMLError as e:
        logger.warning("YAML frontmatter parse failed: %s", e)
        return {}, content

    if metadata is None:
        return {}, body

    return metadata, body


def dumps(metadata: dict | None, body: str) -> str:
    """Serialize (metadata, body) back to a markdown file.

    Empty metadata writes the body unchanged (no delimiters).
    """
    if not metadata:
        return body

    buf = io.StringIO()
    _YAML.dump(metadata, buf)
    return f"---\n{buf.getvalue()}---\n{body}"
