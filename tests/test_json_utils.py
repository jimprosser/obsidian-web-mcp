"""Tests for the json_utils serialization helper."""
import json
from datetime import date, datetime, time

import pytest

from obsidian_vault_mcp.json_utils import _default, dumps


def test_dumps_handles_plain_strings():
    """Pure strings should serialize like normal json.dumps."""
    result = dumps({"name": "Hello", "count": 42})
    assert json.loads(result) == {"name": "Hello", "count": 42}


def test_dumps_handles_date_objects():
    """datetime.date should serialize as ISO 8601 string."""
    payload = {"created": date(2026, 5, 18)}
    result = dumps(payload)
    assert json.loads(result) == {"created": "2026-05-18"}


def test_dumps_handles_datetime_objects():
    """datetime.datetime should serialize with full ISO 8601 timestamp."""
    payload = {"timestamp": datetime(2026, 5, 18, 14, 30, 0)}
    result = dumps(payload)
    assert json.loads(result) == {"timestamp": "2026-05-18T14:30:00"}


def test_dumps_handles_time_objects():
    """datetime.time should serialize as ISO 8601 time string."""
    payload = {"clock": time(9, 15, 30)}
    result = dumps(payload)
    assert json.loads(result) == {"clock": "09:15:30"}


def test_dumps_handles_nested_dates():
    """Dates nested in dicts and lists should all convert."""
    payload = {
        "created": date(2026, 1, 1),
        "tags": ["a", "b"],
        "history": [
            {"day": date(2026, 5, 17), "note": "first"},
            {"day": date(2026, 5, 18), "note": "second"},
        ],
    }
    result = dumps(payload)
    parsed = json.loads(result)
    assert parsed["created"] == "2026-01-01"
    assert parsed["history"][0]["day"] == "2026-05-17"
    assert parsed["history"][1]["day"] == "2026-05-18"


def test_dumps_simulates_frontmatter_payload():
    """Realistic frontmatter dict from python-frontmatter library."""
    fm = {
        "title": "Project Note",
        "created": date(2026, 5, 4),
        "updated": date(2026, 5, 18),
        "tags": ["map", "roadmap"],
        "status": "in-progress",
    }
    payload = {"path": "notes/project.md", "frontmatter": fm}
    result = dumps(payload)
    parsed = json.loads(result)
    assert parsed["frontmatter"]["created"] == "2026-05-04"
    assert parsed["frontmatter"]["updated"] == "2026-05-18"
    assert parsed["frontmatter"]["tags"] == ["map", "roadmap"]


def test_default_raises_for_unsupported_types():
    """Unsupported types should still raise TypeError."""
    class CustomObject:
        pass

    with pytest.raises(TypeError, match="not JSON serializable"):
        _default(CustomObject())


def test_dumps_passes_through_none_and_booleans():
    """None and booleans should pass through unchanged."""
    result = dumps({"key": None, "active": True, "draft": False})
    assert json.loads(result) == {"key": None, "active": True, "draft": False}
