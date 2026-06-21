"""Tests for the write-event seam (register_write_listener + fire_write).

The write-side mirror of FrontmatterIndex.add_change_listener: a process-global
registry that is a true no-op with zero listeners, carries (operation, paths) per
operation, and logs-and-swallows a listener's exceptions so one bad subscriber
can never break a write or starve the others.
"""

import pytest

from obsidian_vault_mcp import write_events


@pytest.fixture(autouse=True)
def _clear_listeners():
    """Each test starts with an empty registry (it is process-global)."""
    write_events._write_listeners.clear()
    yield
    write_events._write_listeners.clear()


def test_fire_with_no_listeners_is_a_noop():
    """Zero listeners => byte-identical stock server: fire must not raise."""
    write_events.fire_write("created", ["a.md"])  # must not raise


def test_registered_listener_receives_operation_and_paths():
    seen = []
    write_events.register_write_listener(lambda op, paths: seen.append((op, paths)))

    write_events.fire_write("created", ["note.md"])

    assert seen == [("created", ["note.md"])]


def test_all_listeners_fire_in_registration_order():
    order = []
    write_events.register_write_listener(lambda op, paths: order.append("first"))
    write_events.register_write_listener(lambda op, paths: order.append("second"))

    write_events.fire_write("updated", ["x.md"])

    assert order == ["first", "second"]


def test_listener_exception_is_swallowed_and_others_still_fire(caplog):
    survived = []
    write_events.register_write_listener(
        lambda op, paths: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    write_events.register_write_listener(lambda op, paths: survived.append(paths))

    # Must not propagate despite the throwing listener.
    write_events.fire_write("deleted", ["gone.md"])

    assert survived == [["gone.md"]]
