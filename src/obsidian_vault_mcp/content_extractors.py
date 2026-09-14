"""In-process read-side content-extractor seam: the read mirror of the write-event seam
(``write_events``) and the index change-listener (#57).

Lets an extension supply text for a file the host cannot read itself -- OCR for a scanned
PDF, a transcript for an audio attachment, a rendered preview -- transparently through
``read_file``, instead of as a separate must-know-about tool. Core stays a no-op callback
list: with zero extractors registered ``read_file`` is byte-identical to the stock server,
the OCR binary / model / subprocess lives entirely downstream in the (fully-trusted)
extension, and an extractor's exception is logged and swallowed.

    from obsidian_vault_mcp.content_extractors import register_content_extractor

    register_content_extractor(lambda path, default_text: ocr(path) or None)

NOTE: a registered extractor changes what ``read_file`` returns for that path. The hook
fires only when the built-in extraction is empty or unsupported, the first non-None result
wins, and a buggy extractor therefore returns wrong text *for that one file* -- bounded to
the file the caller already requested and is authorized to read, but real, so only load
extractors you trust (the #57 extension trust model).
"""

import logging

logger = logging.getLogger(__name__)

# Registered at startup (before serving), consulted during request handling.
_content_extractors: list = []


def register_content_extractor(callback) -> None:
    """Register a ``callback(path: str, default_text: str) -> str | None``.

    Consulted by ``read_file`` ONLY when the built-in extraction is empty or unsupported
    (e.g. a non-UTF-8 / binary file). ``path`` is vault-relative; ``default_text`` is
    whatever the built-in read produced (an empty string when unsupported). Return the
    extracted text, or ``None`` to decline -- the next extractor, then the host's default
    behaviour, applies. With none registered this seam is a true no-op on the stock server.
    Exceptions raised by an extractor are logged and swallowed, never propagated.
    """
    _content_extractors.append(callback)


def apply_content_extractors(path: str, default_text: str) -> str | None:
    """Return the first non-None extractor result for ``path``, or ``None`` if none apply.

    Called inside ``read_file`` at the empty/unsupported branch; a no-op returning ``None``
    when no extractor is registered. An extractor's exception is logged and swallowed so a
    flaky extractor can't break a read.
    """
    for extractor in _content_extractors:
        try:
            result = extractor(path, default_text)
        except Exception:
            logger.warning("Content extractor error for %s", path)
            continue
        if result is not None:
            return result
    return None
