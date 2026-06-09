"""vault_write must not rewrite YAML frontmatter formatting on merge."""

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
