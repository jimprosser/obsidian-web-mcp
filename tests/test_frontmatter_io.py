"""Tests for frontmatter_io.py -- round-trip YAML frontmatter preservation."""

import threading

import pytest
from ruamel.yaml.error import YAMLError

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


def test_roundtrip_preserves_anchors_and_aliases():
    """YAML anchors and aliases survive a round-trip (not expanded or dropped)."""
    content = (
        "---\n"
        "base: &base shared\n"
        "ref: *base\n"
        "---\n"
        "Body.\n"
    )
    metadata, body = frontmatter_io.loads(content)
    out = frontmatter_io.dumps(metadata, body)
    assert out == content
    assert "&base" in out   # anchor kept
    assert "*base" in out   # alias kept, not expanded to a second copy


def test_roundtrip_preserves_standalone_and_inter_key_comments():
    """Full-line comments above and between keys survive a round-trip."""
    content = (
        "---\n"
        "# top-of-block note\n"
        "title: hello\n"
        "# note between keys\n"
        "status: active\n"
        "---\n"
        "Body.\n"
    )
    metadata, body = frontmatter_io.loads(content)
    out = frontmatter_io.dumps(metadata, body)
    assert out == content


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


def test_roundtrip_preserves_crlf_line_endings():
    """A uniformly-CRLF file round-trips byte-identically (no mixed endings)."""
    content = "---\r\ntitle: hello\r\ntags:\r\n  - a\r\n  - b\r\n---\r\nbody line\r\n"
    metadata, body = frontmatter_io.loads(content)
    out = frontmatter_io.dumps(metadata, body)
    assert out == content
    assert "\n" not in out.replace("\r\n", "")  # no bare LF left behind


def test_roundtrip_preserves_long_scalar_unwrapped():
    """A scalar longer than any line-width default is not re-folded on dump."""
    big = "x" * 5000
    content = f"---\nurl: {big}\n---\nbody\n"
    metadata, body = frontmatter_io.loads(content)
    out = frontmatter_io.dumps(metadata, body)
    assert out == content


def test_concurrent_roundtrips_are_isolated():
    """Concurrent loads/dumps must not corrupt shared parser state."""
    errors: list[str] = []
    mismatches = [0]

    def worker(i: int) -> None:
        src = f"---\ntitle: note{i % 5}\ntags:\n  - a\n  - b\n---\nbody {i}\n"
        for _ in range(200):
            try:
                meta, body = frontmatter_io.loads(src)
                if frontmatter_io.dumps(meta, body) != src:
                    mismatches[0] += 1
            except Exception as e:  # noqa: BLE001 - capture anything the singleton leaks
                errors.append(repr(e))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert mismatches[0] == 0


def test_loads_raises_on_malformed_frontmatter():
    """Delimiters present but invalid YAML raises (not silently treated as no frontmatter)."""
    content = "---\nkey: [unclosed\n---\nbody\n"
    with pytest.raises(YAMLError):
        frontmatter_io.loads(content)


def test_loads_no_delimiters_still_returns_empty():
    """Text without delimiters is not 'malformed' -- it just has no frontmatter."""
    content = "key: [unclosed\nthis is plain body text\n"
    metadata, body = frontmatter_io.loads(content)
    assert metadata == {}
    assert body == content


def test_loads_inline_triple_dash_in_value_does_not_close_block():
    """A scalar value containing '---' must not be read as the closing fence."""
    content = "---\nsummary: alpha --- beta\nstatus: active\n---\nbody\n"
    metadata, body = frontmatter_io.loads(content)
    assert metadata["summary"] == "alpha --- beta"
    assert metadata["status"] == "active"  # not dropped into the body
    assert body == "body\n"


def test_loads_literal_block_with_indented_triple_dash_not_truncated():
    """An indented '---' inside a literal block is content, not the closing fence."""
    content = (
        "---\n"
        "description: |\n"
        "  line one\n"
        "  ---\n"
        "  line three\n"
        "status: active\n"
        "---\n"
        "body\n"
    )
    metadata, body = frontmatter_io.loads(content)
    assert "---" in metadata["description"]
    assert "line three" in metadata["description"]
    assert metadata["status"] == "active"  # key after the block survives
    assert body == "body\n"


def test_loads_strips_leading_bom_and_detects_frontmatter():
    """A UTF-8 BOM before the opening '---' must not hide the frontmatter."""
    content = "﻿---\ntitle: kept\n---\nbody\n"
    metadata, body = frontmatter_io.loads(content)
    assert metadata["title"] == "kept"  # frontmatter seen, not treated as absent
    assert body == "body\n"


def test_loads_opening_without_closing_delimiter_fails_closed():
    """An opening '---' with no closing fence raises rather than silently misreading."""
    content = "---\ntitle: no close\nstill: frontmatter\n"
    with pytest.raises(YAMLError):
        frontmatter_io.loads(content)


def test_update_existing_quoted_value_keeps_quote_style():
    """Overwriting an existing key's value retains that key's original quote style."""
    metadata, body = frontmatter_io.loads("---\nstatus: 'active'\npriority: 1\n---\nx\n")
    metadata["status"] = "draft"
    out = frontmatter_io.dumps(metadata, body)
    assert "status: 'draft'" in out   # value changed, single-quote slot kept
    assert "priority: 1" in out


def test_roundtrip_crlf_frontmatter_empty_body():
    """CRLF frontmatter with no body round-trips byte-identically (newline from frontmatter)."""
    content = "---\r\ntitle: hello\r\n---\r\n"
    metadata, body = frontmatter_io.loads(content)
    out = frontmatter_io.dumps(metadata, body)
    assert out == content
