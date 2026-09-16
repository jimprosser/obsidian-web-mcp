"""The read-side content-extractor seam.

The hazard this seam has to survive: read_file is also the read half of every tool that
reads, transforms and writes back. If extracted text reached those tools, a correct OCR
extractor would turn vault_edit on a scanned PDF into "replace the PDF with its OCR
text". So the tests below are built in a fixed order:

1. Prove the extractor really produces text through the read tools. Without that, a
   test asserting "the binary is untouched" also passes when extraction never ran.
2. Then drive every write-back tool through the registered MCP tool - the same entry
   point a client reaches - and assert on the bytes left on disk.

The extractor used here is signature-agnostic (``*args``) on purpose, so the same
negative tests can be run against an earlier revision of this seam and show it failing.
"""

import asyncio
import json

import pytest

from obsidian_vault_mcp import content_extractors, server
from obsidian_vault_mcp.content_extractors import apply_content_extractors, register_content_extractor
from obsidian_vault_mcp.vault import read_file

EXTRACTED = "Rechnung Nr. 4711 extrahiert"
# Not valid UTF-8, so the host cannot read it itself.
BINARY = b"%PDF-1.4\n\xff\xfe\x00\x01 scanned page bytes\n%%EOF\n"


@pytest.fixture(autouse=True)
def _clear_registry():
    content_extractors._content_extractors.clear()
    yield
    content_extractors._content_extractors.clear()


@pytest.fixture
def scan(vault_dir):
    target = vault_dir / "scan.pdf"
    target.write_bytes(BINARY)
    return target


@pytest.fixture
def extractor():
    calls = []

    def extract(*args):
        calls.append(args)
        return EXTRACTED

    register_content_extractor(extract)
    return calls


def call_tool(name: str, arguments: dict) -> dict:
    """Call a tool the way a client does: through the FastMCP registration, including
    the server's input models and audit wrapper, not the bare implementation function."""
    result = asyncio.run(server.mcp.call_tool(name, arguments))
    if isinstance(result, tuple):  # (content blocks, structured output)
        result = result[0]
    text = "".join(getattr(block, "text", "") for block in result)
    return json.loads(text)


# --- 1. The extractor genuinely works through the read tools -------------------------

def test_vault_read_returns_extracted_text(scan, extractor):
    result = call_tool("vault_read", {"path": "scan.pdf"})

    assert result["content"] == EXTRACTED, result
    assert result["metadata"]["size"] == len(BINARY)


def test_vault_batch_read_returns_extracted_text(scan, extractor):
    result = call_tool("vault_batch_read", {"paths": ["scan.pdf", "test-note.md"]})
    by_path = {entry["path"]: entry for entry in result["files"]}

    assert by_path["scan.pdf"]["content"] == EXTRACTED, result
    assert "test note" in by_path["test-note.md"]["content"]


def test_extractor_receives_relative_and_resolved_path(scan, extractor):
    call_tool("vault_read", {"path": "scan.pdf"})

    assert extractor == [("scan.pdf", scan.resolve())]


# --- 2. No write-back tool ever sees extracted text -----------------------------------

WRITE_BACK_TOOLS = {
    "vault_edit": {"path": "scan.pdf", "edits": [{"old_text": EXTRACTED, "new_text": "X"}]},
    "vault_append": {"path": "scan.pdf", "content": "angehaengt"},
    "vault_batch_frontmatter_update": {"updates": [{"path": "scan.pdf", "fields": {"status": "done"}}]},
    "vault_write merge_frontmatter": {
        "path": "scan.pdf",
        "content": "---\nstatus: done\n---\nneu\n",
        "merge_frontmatter": True,
    },
}


@pytest.mark.parametrize("label", sorted(WRITE_BACK_TOOLS))
def test_write_back_tool_leaves_the_binary_untouched(scan, extractor, label):
    # Precondition inside the same test, so no ordering can make this pass while the
    # extractor is not actually producing text.
    assert call_tool("vault_read", {"path": "scan.pdf"})["content"] == EXTRACTED
    extractor.clear()

    name = label.split()[0]
    result = call_tool(name, WRITE_BACK_TOOLS[label])

    assert scan.read_bytes() == BINARY, f"{label} replaced the binary on disk"
    assert "error" in json.dumps(result), f"{label} did not report the failure: {result}"
    assert extractor == [], f"{label} consulted the extractor"


def test_read_file_does_not_consult_extractors_unless_asked(scan, extractor):
    with pytest.raises(UnicodeDecodeError):
        read_file("scan.pdf")

    assert extractor == []


# --- 3. The seam stays out of the way -------------------------------------------------

def test_nothing_registered_binary_read_fails_as_before(scan):
    result = call_tool("vault_read", {"path": "scan.pdf"})

    assert "error" in result
    assert apply_content_extractors("scan.pdf", scan) is None


def test_utf8_text_never_reaches_an_extractor(vault_dir, extractor):
    result = call_tool("vault_read", {"path": "test-note.md"})

    assert "test note" in result["content"]
    assert extractor == []


def test_empty_file_is_not_offered_to_extractors(vault_dir, extractor):
    """An empty note is a note, not an unreadable file. Filling it in would let the
    next append persist extractor output into a file the user created empty."""
    (vault_dir / "leer.md").write_text("", encoding="utf-8")

    assert call_tool("vault_read", {"path": "leer.md"})["content"] == ""
    assert extractor == []


def test_first_non_none_wins_and_exceptions_are_swallowed(scan):
    def boom(relative_path, path):
        raise RuntimeError("extractor blew up")

    register_content_extractor(boom)
    register_content_extractor(lambda relative_path, path: None)
    register_content_extractor(lambda relative_path, path: "second")
    register_content_extractor(lambda relative_path, path: "third")

    assert call_tool("vault_read", {"path": "scan.pdf"})["content"] == "second"


def test_hardlinked_binary_never_reaches_an_extractor(vault_dir, tmp_path, extractor):
    """The host refuses hardlinks before extraction (#79), so an extractor cannot be
    used to read a file outside the vault through a link."""
    import os

    outside = tmp_path / "outside.pdf"
    outside.write_bytes(BINARY)
    (vault_dir / "copy.pdf").write_bytes(BINARY)
    try:
        os.link(outside, vault_dir / "linked.pdf")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")

    assert call_tool("vault_read", {"path": "copy.pdf"})["content"] == EXTRACTED
    extractor.clear()

    result = call_tool("vault_read", {"path": "linked.pdf"})

    assert "error" in result and EXTRACTED not in json.dumps(result)
    assert extractor == []
