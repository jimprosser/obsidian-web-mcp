"""The content-extractor seam against a real server process, over HTTP.

The server is serve() in its own process with an extension that registers an extractor
from before_indexes_start, the way an extension would ship it. A client authenticates
with a bearer token and calls the tools over MCP streamable HTTP.

The hazard is proven in the same run before the protection is checked: vault_read really
returns the extracted text for the binary. Only then do vault_edit and vault_append, which
read in order to write back, have something they could have written over the file.
"""

import pytest

from ._live_server import call_tool_over_http, live_server

EXTRACTED = "Rechnung Nr. 4711 extrahiert"
BINARY = b"%PDF-1.4\n\xff\xfe\x00\x01 scanned page bytes\n%%EOF\n"

BOOTSTRAP = f'''
from obsidian_vault_mcp import content_extractors
from obsidian_vault_mcp.extensions import Extension


class ExtractorExtension(Extension):
    def before_indexes_start(self, frontmatter_index):
        # Signature-agnostic on purpose, so this test also runs against earlier
        # revisions of the seam.
        content_extractors.register_content_extractor(
            lambda *args: {EXTRACTED!r} if str(args[0]).endswith(".pdf") else None
        )


EXTENSIONS = [ExtractorExtension()]
'''


@pytest.fixture
def vault(tmp_path):
    v = tmp_path / "vault"
    v.mkdir()
    (v / "scan.pdf").write_bytes(BINARY)
    (v / "note.md").write_text("# Note\n\nbody\n", encoding="utf-8")
    return v


def test_extracted_text_is_readable_but_never_written_back(tmp_path, vault):
    with live_server(tmp_path, vault, bootstrap=BOOTSTRAP) as (base_url, _log):
        read = call_tool_over_http(base_url, "vault_read", {"path": "scan.pdf"})
        assert read.get("content") == EXTRACTED, f"the extractor is not live, nothing below is proven: {read}"

        batch = call_tool_over_http(base_url, "vault_batch_read", {"paths": ["scan.pdf"]})
        assert batch["files"][0].get("content") == EXTRACTED, batch

        edit = call_tool_over_http(
            base_url, "vault_edit", {"path": "scan.pdf", "edits": [{"old_text": EXTRACTED, "new_text": "X"}]}
        )
        assert (vault / "scan.pdf").read_bytes() == BINARY, f"vault_edit replaced the binary: {edit}"
        assert "error" in edit, edit

        append = call_tool_over_http(base_url, "vault_append", {"path": "scan.pdf", "content": "angehaengt"})
        assert (vault / "scan.pdf").read_bytes() == BINARY, f"vault_append replaced the binary: {append}"
        assert "error" in append, append

        frontmatter = call_tool_over_http(
            base_url, "vault_batch_frontmatter_update", {"updates": [{"path": "scan.pdf", "fields": {"status": "done"}}]}
        )
        assert (vault / "scan.pdf").read_bytes() == BINARY, f"frontmatter update replaced the binary: {frontmatter}"

        # The seam stays out of ordinary notes.
        note = call_tool_over_http(base_url, "vault_read", {"path": "note.md"})
        assert "body" in note.get("content", ""), note
