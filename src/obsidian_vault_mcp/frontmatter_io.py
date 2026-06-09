"""YAML frontmatter I/O that preserves formatting across round-trips.

Uses ruamel.yaml in round-trip mode so quote style, comments, block/flow
style, boolean forms (yes/no vs true/false), and key order survive a
load-then-dump cycle. PyYAML (via python-frontmatter) normalizes all of
these, which rewrites users' carefully-formatted frontmatter on every
update.
"""

from __future__ import annotations

import io
import re
import sys

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError  # noqa: F401 - re-exported for callers

_FRONTMATTER_RE = re.compile(
    r"\A---[ \t]*\r?\n(.*?)(?:\r?\n)?---[ \t]*\r?\n?(.*)\Z",
    re.DOTALL,
)


def _make_yaml() -> YAML:
    """Build a fresh round-trip handler.

    ruamel.yaml's YAML object holds mutable parser/emitter state and is not
    reentrant, so a module-level singleton corrupts under concurrent use
    (FastMCP runs sync tools in a threadpool). Construct one per call --
    cheap for human-triggered writes.
    """
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    # Disable line wrapping: any finite width re-folds long scalars (URLs,
    # descriptions) on dump, which is exactly the churn this module avoids.
    yaml.width = sys.maxsize
    yaml.indent(mapping=2, sequence=4, offset=2)
    return yaml


def loads(content: str) -> tuple[dict, str]:
    """Parse a markdown file into (metadata, body).

    When frontmatter is present, metadata is a ruamel.yaml CommentedMap that
    retains the original formatting for round-trip dumping. When absent,
    returns ({}, content). Raises YAMLError when delimiters are present but
    the enclosed YAML is invalid -- the caller decides how to handle it,
    rather than silently conflating "no frontmatter" with "broken frontmatter".
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

    metadata = _make_yaml().load(raw_yaml)

    if metadata is None:
        return {}, body

    return metadata, body


def dumps(metadata: dict | None, body: str) -> str:
    """Serialize (metadata, body) back to a markdown file.

    Empty metadata writes the body unchanged (no delimiters). The frontmatter
    block matches the body's line endings so a CRLF file never gains mixed
    endings (ruamel always emits "\\n").
    """
    if not metadata:
        return body

    buf = io.StringIO()
    _make_yaml().dump(metadata, buf)
    yaml_text = buf.getvalue()

    newline = "\r\n" if "\r\n" in body else "\n"
    if newline != "\n":
        yaml_text = yaml_text.replace("\n", newline)

    return f"---{newline}{yaml_text}---{newline}{body}"
