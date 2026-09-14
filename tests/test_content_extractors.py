"""Tests for the read-side content-extractor seam.

Exercises the seam through the real ``read_file`` (not just the registry helper), including
the byte-identical no-op when nothing is registered and the negative/abuse cases.
"""

import pytest

from obsidian_vault_mcp import content_extractors
from obsidian_vault_mcp.content_extractors import (
    apply_content_extractors,
    register_content_extractor,
)
from obsidian_vault_mcp.vault import read_file


@pytest.fixture(autouse=True)
def _clear_registry():
    content_extractors._content_extractors.clear()
    yield
    content_extractors._content_extractors.clear()


# --- byte-identical no-op with nothing registered ---

def test_no_extractor_text_file_unchanged(vault_dir):
    (vault_dir / "note.md").write_text("hello body\n", encoding="utf-8")
    content, _ = read_file("note.md")
    assert content == "hello body\n"


def test_no_extractor_binary_still_raises(vault_dir):
    # Stock behaviour: a non-UTF-8 file raises; with no extractor that must be preserved.
    (vault_dir / "scan.pdf").write_bytes(b"%PDF-1.4\xff\xfe binary bytes")
    with pytest.raises(UnicodeDecodeError):
        read_file("scan.pdf")


def test_apply_empty_registry_returns_none():
    assert apply_content_extractors("x.md", "") is None


# --- an extractor fills the empty/unsupported branches ---

def test_extractor_supplies_text_for_unsupported(vault_dir):
    (vault_dir / "scan.pdf").write_bytes(b"%PDF-1.4\xff\xfe binary bytes")
    register_content_extractor(lambda path, default_text: f"ocr:{path}")
    content, metadata = read_file("scan.pdf")
    assert content == "ocr:scan.pdf"
    assert metadata["size"] > 0  # metadata still comes from the real file


def test_extractor_supplies_text_for_empty_file(vault_dir):
    (vault_dir / "empty.md").write_text("", encoding="utf-8")
    register_content_extractor(lambda path, default_text: "filled in")
    content, _ = read_file("empty.md")
    assert content == "filled in"


def test_first_non_none_wins(vault_dir):
    (vault_dir / "scan.pdf").write_bytes(b"\xff\xfe")
    register_content_extractor(lambda path, default_text: None)   # declines
    register_content_extractor(lambda path, default_text: "second")
    register_content_extractor(lambda path, default_text: "third")
    content, _ = read_file("scan.pdf")
    assert content == "second"


def test_extractor_exception_is_swallowed(vault_dir):
    (vault_dir / "scan.pdf").write_bytes(b"\xff\xfe")

    def boom(path, default_text):
        raise RuntimeError("extractor blew up")

    register_content_extractor(boom)
    register_content_extractor(lambda path, default_text: "recovered")
    content, _ = read_file("scan.pdf")
    assert content == "recovered"


def test_extractor_not_consulted_for_normal_text(vault_dir):
    # Built-in extraction succeeds, so the extractor must not run / not override.
    (vault_dir / "note.md").write_text("real body\n", encoding="utf-8")
    register_content_extractor(lambda path, default_text: "SHOULD NOT APPEAR")
    content, _ = read_file("note.md")
    assert content == "real body\n"
