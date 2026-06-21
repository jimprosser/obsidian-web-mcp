"""In-process write-event seam: the write-side mirror of
``FrontmatterIndex.add_change_listener``.

Lets an extension react to a vault mutation *as an operation* -- a provenance-aware
git commit, an audit log, a webhook -- which the watcher-driven change-listener
can't express (it only reports ``(abs_path, exists)`` for ``.md`` files). Core stays
a no-op callback list: with zero listeners ``fire_write`` does nothing, side effects
live entirely downstream in the (fully-trusted) extension, and a listener's exception
is logged and swallowed so it can't break a write or starve the other listeners.

The publish side is public on purpose -- called by the core mutation tools AND by an
extension after its own write (e.g. attachment bytes on a path no core tool touches),
so one stream carries both::

    from obsidian_vault_mcp.write_events import register_write_listener, fire_write

    register_write_listener(lambda op, paths: ...)   # subscribe
    fire_write("created", ["attachments/img.png"])    # publish (from an extension)
"""

import logging

logger = logging.getLogger(__name__)

# Registered at startup (before serving), fired during request handling.
_write_listeners: list = []


def register_write_listener(callback) -> None:
    """Register a ``callback(operation: str, paths: list[str])`` for vault mutations.

    Invoked once per successful mutation operation, after the write lands. ``operation``
    is one of "created", "updated", "moved", "deleted"; ``paths`` are vault-relative
    (a move passes ``[source, destination]``; a batch passes only the paths it wrote).
    With no listeners registered this seam is a true no-op on the stock server.
    Exceptions raised by a listener are logged and swallowed, never propagated.
    """
    _write_listeners.append(callback)


def fire_write(operation: str, paths: list[str]) -> None:
    """Notify every write listener of a mutation; a no-op with none registered.

    Called by the core mutation tools at their success path, and public so an
    extension can publish its own writes to the same stream.
    """
    for listener in _write_listeners:
        try:
            listener(operation, paths)
        except Exception:
            logger.warning("Write listener error for %s %s", operation, paths)
