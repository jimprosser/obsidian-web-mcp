"""Tests for frontmatter_io.py -- round-trip YAML frontmatter preservation."""

from obsidian_vault_mcp import frontmatter_io


def test_loads_no_frontmatter_returns_empty_metadata():
    """A file with no frontmatter delimiters returns empty metadata and full body."""
    content = "Just body text, no frontmatter.\n"
    metadata, body = frontmatter_io.loads(content)
    assert metadata == {}
    assert body == content


def test_loads_parses_metadata_and_body():
    """A file with frontmatter splits into metadata dict and body."""
    content = "---\nstatus: active\ntype: note\n---\n\nBody text here.\n"
    metadata, body = frontmatter_io.loads(content)
    assert metadata["status"] == "active"
    assert metadata["type"] == "note"
    assert "Body text here." in body


def test_loads_empty_frontmatter_block():
    """A file with empty frontmatter (---\\n---\\n) returns empty metadata."""
    content = "---\n---\nBody after empty frontmatter.\n"
    metadata, body = frontmatter_io.loads(content)
    assert metadata == {} or metadata is None or len(metadata) == 0
    assert "Body after empty frontmatter." in body


def test_roundtrip_preserves_quote_styles():
    """Reading and re-dumping unchanged frontmatter produces byte-identical output."""
    content = (
        "---\n"
        "unquoted: value1\n"
        "single: 'value2'\n"
        "double: \"value3\"\n"
        "---\n"
        "Body.\n"
    )
    metadata, body = frontmatter_io.loads(content)
    out = frontmatter_io.dumps(metadata, body)
    assert out == content


def test_roundtrip_preserves_yes_no_booleans():
    """yes/no boolean style is preserved, not normalized to true/false."""
    content = "---\nactive: yes\narchived: no\n---\n\nBody.\n"
    metadata, body = frontmatter_io.loads(content)
    out = frontmatter_io.dumps(metadata, body)
    assert "yes" in out
    assert "no" in out
    assert "true" not in out
    assert "false" not in out


def test_roundtrip_preserves_block_list_style():
    """Block-style lists stay block-style (not flattened to flow style)."""
    content = (
        "---\n"
        "tags:\n"
        "  - alpha\n"
        "  - beta\n"
        "  - gamma\n"
        "---\n"
        "Body.\n"
    )
    metadata, body = frontmatter_io.loads(content)
    out = frontmatter_io.dumps(metadata, body)
    assert out == content


def test_roundtrip_preserves_literal_block_string():
    """Literal-block multi-line strings (|) keep their style and chomping."""
    content = (
        "---\n"
        "description: |\n"
        "  Line one.\n"
        "  Line two.\n"
        "---\n"
        "Body.\n"
    )
    metadata, body = frontmatter_io.loads(content)
    out = frontmatter_io.dumps(metadata, body)
    assert out == content


def test_roundtrip_preserves_comments():
    """Inline comments in frontmatter survive round-trip."""
    content = (
        "---\n"
        "status: active  # current project state\n"
        "priority: 1\n"
        "---\n"
        "Body.\n"
    )
    metadata, body = frontmatter_io.loads(content)
    out = frontmatter_io.dumps(metadata, body)
    assert "# current project state" in out


def test_update_field_preserves_other_formatting():
    """Updating one field does not reformat unrelated fields."""
    content = (
        "---\n"
        "status: 'active'\n"
        "tags:\n"
        "  - alpha\n"
        "  - beta\n"
        "priority: 1\n"
        "---\n"
        "Body.\n"
    )
    metadata, body = frontmatter_io.loads(content)
    metadata["priority"] = 2
    out = frontmatter_io.dumps(metadata, body)
    assert "status: 'active'" in out
    assert "- alpha" in out
    assert "- beta" in out
    assert "priority: 2" in out


def test_dumps_no_frontmatter_writes_body_unchanged():
    """Empty metadata produces the body only, no delimiters."""
    body = "Just plain body content.\n"
    out = frontmatter_io.dumps({}, body)
    assert out == body


def test_dumps_ends_with_newline_after_body():
    """Output preserves body exactly as passed (no added/stripped trailing newlines)."""
    content = "---\nkey: value\n---\nBody without trailing newline"
    metadata, body = frontmatter_io.loads(content)
    out = frontmatter_io.dumps(metadata, body)
    assert out.endswith("Body without trailing newline")
