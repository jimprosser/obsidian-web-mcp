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
from pathlib import Path

logger = logging.getLogger(__name__)

# Registered at startup (before serving), consulted during request handling.
_content_extractors: list = []


def register_content_extractor(callback) -> None:
    """Register a ``callback(relative_path: str, path: Path) -> str | None``.

    Consulted only by the read tools, and only for a file that is not valid UTF-8.
    ``relative_path`` is the vault-relative path the client asked for; ``path`` is the
    host-resolved absolute path, already past the host's containment and hardlink checks,
    so an extractor never has to resolve or re-validate it. Return the extracted text, or
    ``None`` to decline -- the next extractor, then the host's default behaviour, applies.
    Exceptions raised by an extractor are logged and swallowed, never propagated.
    """
    _content_extractors.append(callback)


def apply_content_extractors(relative_path: str, path: Path) -> str | None:
    """Return the first non-None extractor result, or ``None`` if none apply."""
    for extractor in _content_extractors:
        try:
            result = extractor(relative_path, path)
        except Exception:
            logger.warning("Content extractor error for %s", relative_path, exc_info=True)
            continue
        if result is not None:
            return result
    return None
