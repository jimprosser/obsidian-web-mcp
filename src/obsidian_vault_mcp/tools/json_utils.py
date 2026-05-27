"""JSON serialization helpers for vault tools."""

import json


def dumps(obj: object) -> str:
    """Serialize obj to JSON, converting non-serializable types (e.g. datetime.date) to str."""
    return json.dumps(obj, default=str)
