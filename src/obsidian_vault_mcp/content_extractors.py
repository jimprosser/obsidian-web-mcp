"""In-process read-side content-extractor seam: the read mirror of the write-event seam
(``write_events``) and the index change-listener (#57).

Lets an extension supply text for a file the host cannot read itself -- OCR for a scanned
PDF or a screenshot, a transcript for an audio attachment -- through the read tools,
instead of as a separate must-know-about tool. Core stays a no-op callback list: with
zero extractors registered every read is byte-identical to the stock server, the OCR
binary / model / subprocess lives entirely downstream in the (fully-trusted) extension,
and an extractor's exception is logged and swallowed.

    from obsidian_vault_mcp.content_extractors import register_content_extractor

    register_content_extractor(lambda relative_path, path: ocr(path))

Only ``vault_read`` and ``vault_batch_read`` consult extractors. ``read_file`` is also
the read half of every tool that reads, transforms and writes back (``vault_edit``,
``vault_append``, ``vault_batch_frontmatter_update``, ``vault_write`` with
``merge_frontmatter``, the canvas tools); if those received extracted text they would
write it over the binary. They call ``read_file`` without ``extract=True`` and so keep
failing on a file that is not UTF-8, exactly as without an extractor.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Default search patterns (#96). What an extractor makes readable is often persisted as a
# file next to its source (an OCR sidecar, "scan.pdf.ocr.txt"), and vault_search looks at
# notes only by default, so that text was invisible to a search that did not name the
# pattern. An extension adds its pattern here; it applies only when the caller leaves
# file_pattern at its default, and with nothing registered the search is unchanged.
DEFAULT_SEARCH_PATTERN = "*.md"
_search_patterns: list[str] = []
# A filename glob: no whitespace, no path separator, not a ripgrep negation ("!") or
# option ("-"), at most as long as vault_search's own file_pattern argument.
_SEARCH_PATTERN = re.compile(r"[^\s/\\!\-][^\s/\\]{0,49}")

# Registered at startup (before serving), consulted during request handling.
_content_extractors: list = []


def register_content_extractor(callback) -> None:
    """Register a ``callback(relative_path: str, path: Path) -> str | None``.

    Consulted only by the read tools, and only for a file that is not valid UTF-8.
    ``relative_path`` is the vault-relative path the client asked for; ``path`` is the
    host-resolved absolute path, already resolved and checked by the host (containment and
    the hardlink refusal). Return the extracted text, or ``None`` to decline -- the next
    extractor, then the host's default behaviour, applies. Anything that is not a ``str``
    counts as a decline, and an exception is logged and swallowed, never propagated.
    """
    _content_extractors.append(callback)


def register_search_pattern(pattern: str) -> None:
    """Add a filename glob (e.g. ``"*.ocr.txt"``) to vault_search's default patterns.

    Called from an extension's ``register_tools``. Applies only when a caller leaves
    ``file_pattern`` at its default; an explicit ``file_pattern`` is used exactly as given.
    Registering a pattern twice, or the default ``*.md``, changes nothing.
    """
    if not isinstance(pattern, str) or not _SEARCH_PATTERN.fullmatch(pattern):
        raise ValueError(
            f"Search pattern must be a filename glob without whitespace or path separators, "
            f"not starting with '!' or '-', at most 50 characters: {pattern!r}"
        )
    if pattern != DEFAULT_SEARCH_PATTERN and pattern not in _search_patterns:
        _search_patterns.append(pattern)


def default_search_patterns() -> list[str]:
    """The patterns vault_search uses when the caller gives none."""
    return [DEFAULT_SEARCH_PATTERN, *_search_patterns]


def apply_content_extractors(relative_path: str, path: Path) -> str | None:
    """Return the first ``str`` extractor result, or ``None`` if none apply."""
    for extractor in _content_extractors:
        try:
            result = extractor(relative_path, path)
        except Exception:
            logger.warning("Content extractor error for %s", relative_path, exc_info=True)
            continue
        if result is None:
            continue
        if not isinstance(result, str):
            logger.warning(
                "Content extractor for %s returned %s, not str; declining",
                relative_path,
                type(result).__name__,
            )
            continue
        return result
    return None
