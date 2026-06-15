"""YAML frontmatter I/O that preserves formatting across round-trips.

Uses ruamel.yaml in round-trip mode so quote style, comments, block/flow
style, boolean forms (yes/no vs true/false), and key order survive a
load-then-dump cycle. PyYAML (via python-frontmatter) normalizes all of
these, which rewrites users' carefully-formatted frontmatter on every
update.
"""

from __future__ import annotations

import io
import sys

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError  # re-exported for callers

_BOM = "﻿"

# Carries the source file's line ending from loads() to dumps() so an
# all-frontmatter file (CRLF frontmatter, empty/LF body) round-trips
# byte-identically instead of inferring the newline from the body alone.
_NEWLINE_ATTR = "_fm_newline"


def _is_fence(line: str) -> bool:
    """True for a frontmatter delimiter line: exactly ``---`` on its own line.

    Trailing spaces/tabs and a CR (CRLF files) are tolerated; leading
    indentation is not, so a ``---`` inside an indented literal block or
    mid-scalar text is never mistaken for the closing fence.
    """
    return line.rstrip("\r\n").rstrip(" \t") == "---"


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

    The frontmatter boundary is matched line-by-line: only a line that is
    exactly ``---`` (no indentation) opens or closes the block. This keeps a
    ``---`` appearing inside a scalar value or an indented literal block from
    being misread as the closing fence and silently dropping later keys. An
    opening fence with no closing fence raises (fails closed) rather than
    treating the whole file as bodyless frontmatter. A leading UTF-8 BOM is
    stripped before matching so BOM-prefixed files are not seen as having no
    frontmatter (which would drop it entirely on a merge write).
    """
    if content.startswith(_BOM):
        content = content[len(_BOM):]

    lines = content.splitlines(keepends=True)
    if not lines or not _is_fence(lines[0]):
        return {}, content

    close_idx = next(
        (i for i in range(1, len(lines)) if _is_fence(lines[i])),
        None,
    )
    if close_idx is None:
        raise YAMLError(
            "unterminated frontmatter: opening '---' has no closing '---' line"
        )

    raw_yaml = "".join(lines[1:close_idx])
    body = "".join(lines[close_idx + 1:])
    newline = "\r\n" if lines[0].endswith("\r\n") else "\n"

    if raw_yaml.strip() == "":
        return {}, body

    # Ensure the YAML text ends with a newline so ruamel correctly parses
    # trailing-newline chomping on literal/folded block scalars at EOF.
    if not raw_yaml.endswith("\n"):
        raw_yaml += "\n"

    metadata = _make_yaml().load(raw_yaml)

    if metadata is None:
        return {}, body

    try:
        setattr(metadata, _NEWLINE_ATTR, newline)
    except (AttributeError, TypeError):
        pass  # non-mapping frontmatter; dumps falls back to body inference

    return metadata, body


def dumps(metadata: dict | None, body: str) -> str:
    """Serialize (metadata, body) back to a markdown file.

    Empty metadata writes the body unchanged (no delimiters). The frontmatter
    block uses the source file's line ending (recorded by loads) when known,
    otherwise the body's, so a CRLF file never gains mixed endings (ruamel
    always emits "\\n") even when its body is empty or LF.
    """
    if not metadata:
        return body

    buf = io.StringIO()
    _make_yaml().dump(metadata, buf)
    yaml_text = buf.getvalue()

    newline = getattr(metadata, _NEWLINE_ATTR, None)
    if newline is None:
        newline = "\r\n" if "\r\n" in body else "\n"
    if newline != "\n":
        yaml_text = yaml_text.replace("\n", newline)

    return f"---{newline}{yaml_text}---{newline}{body}"
