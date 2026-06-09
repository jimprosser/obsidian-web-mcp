"""vault_write must not rewrite YAML frontmatter formatting on merge."""

import json

from obsidian_vault_mcp import config
from obsidian_vault_mcp.tools.write import vault_write


def test_merge_frontmatter_preserves_quotes_and_block_lists(vault_dir):
    path = "fmt.md"
    (config.VAULT_PATH / path).write_text(
        "---\n"
        "title: 'single quoted'\n"
        "tags:\n"
        "  - alpha\n"
        "  - beta\n"
        "pinned: yes\n"
        "---\n"
        "body\n"
    )

    # New frontmatter is carried in the content itself (upstream merge contract).
    new_content = "---\nstatus: draft\n---\nbody\n"
    vault_write(path, new_content, create_dirs=True, merge_frontmatter=True)

    result = (config.VAULT_PATH / path).read_text()
    assert "title: 'single quoted'" in result   # quote style kept
    assert "  - alpha" in result                 # block list kept (not flow)
    assert "pinned: yes" in result               # yes/no not rewritten
    assert "status: draft" in result             # new key merged


def test_merge_aborts_on_malformed_existing_frontmatter(vault_dir):
    """Malformed existing frontmatter aborts the merge and leaves the file untouched."""
    path = "broken.md"
    original = "---\nkey: [unclosed\n---\noriginal body\n"
    (config.VAULT_PATH / path).write_text(original)

    result = json.loads(vault_write(path, "---\nstatus: draft\n---\nbody\n",
                                    create_dirs=True, merge_frontmatter=True))

    assert result["written"] is False
    assert "malformed" in result["error"].lower()
    # File is unchanged -- no silent data loss.
    assert (config.VAULT_PATH / path).read_text() == original


def test_merge_aborts_on_malformed_new_frontmatter(vault_dir):
    """Malformed new frontmatter aborts the merge rather than nesting a --- block."""
    path = "fmt.md"
    original = "---\ntitle: kept\n---\nbody\n"
    (config.VAULT_PATH / path).write_text(original)

    result = json.loads(vault_write(path, "---\nstatus: [unclosed\n---\nbody\n",
                                    create_dirs=True, merge_frontmatter=True))

    assert result["written"] is False
    assert (config.VAULT_PATH / path).read_text() == original
