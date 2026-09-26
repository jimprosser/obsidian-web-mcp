"""A binary type is decided by its extension, not by whether its bytes decode (#95).

A PDF whose bytes are all ASCII (no binary marker comment, uncompressed streams) decodes
as UTF-8. On main, vault_read returned its PDF syntax, the content extractors were never
asked, and vault_edit changed it: the stream length and xref offsets no longer matched
and a strict reader rejected the file. The fixture is exactly such a PDF, and every case
goes through the registered tool.
"""

import asyncio
import json

import pytest

from obsidian_vault_mcp import content_extractors, server


def ascii_pdf(text: str) -> bytes:
    stream = f"BT\n/F1 24 Tf\n72 100 Td\n({text}) Tj\nET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    parts, offsets = [b"%PDF-1.4\n"], []  # no binary marker: every byte is ASCII
    for index, obj in enumerate(objects, start=1):
        offsets.append(sum(map(len, parts)))
        parts.append(f"{index} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = sum(map(len, parts))
    parts.append(b"xref\n0 6\n0000000000 65535 f \n")
    parts += [f"{o:010d} 00000 n \n".encode() for o in offsets]
    parts.append(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return b"".join(parts)


PDF = ascii_pdf("Invoice total 1200 EUR")


def call_tool(name: str, arguments: dict) -> dict:
    result = asyncio.run(server.mcp.call_tool(name, arguments))
    if isinstance(result, tuple):
        result = result[0]
    return json.loads("".join(getattr(block, "text", "") for block in result))


@pytest.fixture
def pdf(vault_dir):
    target = vault_dir / "invoice.pdf"
    target.write_bytes(PDF)
    PDF.decode("utf-8")  # the premise: this file is valid UTF-8
    return target


@pytest.fixture
def extractor():
    seen = []

    def extract(relative_path, path):
        seen.append(relative_path)
        return "EXTRACTED: Invoice total 1200 EUR"

    content_extractors.register_content_extractor(extract)
    yield seen
    content_extractors._content_extractors.clear()


def test_vault_read_hands_the_pdf_to_the_extractors(pdf, extractor):
    result = call_tool("vault_read", {"path": "invoice.pdf"})

    assert result["content"].startswith("EXTRACTED"), result
    assert result["metadata"]["extracted"] is True
    assert extractor == ["invoice.pdf"]


def test_without_an_extractor_vault_read_refuses_instead_of_returning_pdf_syntax(pdf):
    result = call_tool("vault_read", {"path": "invoice.pdf"})

    assert "%PDF" not in json.dumps(result)
    assert "binary file" in result.get("error", ""), result


@pytest.mark.parametrize("tool,arguments", [
    ("vault_edit", {"path": "invoice.pdf", "edits": [{"old_text": "1200", "new_text": "12000"}]}),
    ("vault_append", {"path": "invoice.pdf", "content": "\nappended\n"}),
    ("vault_batch_frontmatter_update", {"updates": [{"path": "invoice.pdf", "fields": {"status": "paid"}}]}),
    ("vault_write", {"path": "invoice.pdf", "content": "---\na: 1\n---\n", "merge_frontmatter": True}),
    ("vault_write", {"path": "invoice.pdf", "content": "replaced by text\n"}),
])
def test_every_text_write_leaves_the_pdf_untouched(pdf, extractor, tool, arguments):
    result = call_tool(tool, arguments)

    assert pdf.read_bytes() == PDF, f"{tool} changed the PDF: {result}"
    assert "error" in json.dumps(result), result


def test_a_text_write_cannot_create_a_binary_type(vault_dir):
    result = call_tool("vault_write", {"path": "new.pdf", "content": "%PDF-1.4 fake\n"})

    assert "binary file type" in result.get("error", ""), result
    assert not (vault_dir / "new.pdf").exists()


def test_upper_case_extensions_count_too(vault_dir):
    (vault_dir / "SCAN.PDF").write_bytes(PDF)

    result = call_tool("vault_edit", {"path": "SCAN.PDF", "edits": [{"old_text": "1200", "new_text": "12000"}]})

    assert (vault_dir / "SCAN.PDF").read_bytes() == PDF, result


def test_binary_writes_still_work(vault_dir):
    """Guard: the refusal sits in write_file_atomic, not in the placement binary writes share."""
    import base64

    result = call_tool("vault_write_binary", {"path": "copy.pdf", "media_type": "application/pdf",
                                              "data": base64.b64encode(PDF).decode()})

    assert result.get("created") is True, result
    assert (vault_dir / "copy.pdf").read_bytes() == PDF


def test_notes_are_unaffected(vault_dir):
    """Guard: an ordinary note still reads and edits as text."""
    (vault_dir / "n.md").write_text("Der Betrag ist 1200.\n", encoding="utf-8")

    assert call_tool("vault_read", {"path": "n.md"})["content"] == "Der Betrag ist 1200.\n"
    call_tool("vault_edit", {"path": "n.md", "edits": [{"old_text": "1200", "new_text": "12000"}]})
    assert (vault_dir / "n.md").read_text(encoding="utf-8") == "Der Betrag ist 12000.\n"
