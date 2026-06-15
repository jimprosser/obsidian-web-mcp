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

    assert result["created"] is False
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

    assert result["created"] is False
    assert (config.VAULT_PATH / path).read_text() == original


def test_merge_keeps_keys_when_value_contains_triple_dash(vault_dir):
    """A value containing '---' must not truncate the frontmatter and drop later keys."""
    path = "fmt.md"
    (config.VAULT_PATH / path).write_text(
        "---\nsummary: alpha --- beta\nstatus: active\n---\nbody\n"
    )

    vault_write(path, "---\npriority: 1\n---\nbody\n",
                create_dirs=True, merge_frontmatter=True)

    result = (config.VAULT_PATH / path).read_text()
    assert "summary: alpha --- beta" in result  # inline --- preserved verbatim
    assert "status: active" in result            # key after it not dropped
    assert "priority: 1" in result               # new key merged


def test_merge_keeps_bom_prefixed_existing_frontmatter(vault_dir):
    """A BOM-prefixed existing file must not have its frontmatter dropped on merge."""
    path = "fmt.md"
    (config.VAULT_PATH / path).write_text("﻿---\ntitle: kept\n---\nbody\n")

    vault_write(path, "---\nstatus: draft\n---\nbody\n",
                create_dirs=True, merge_frontmatter=True)

    result = (config.VAULT_PATH / path).read_text()
    assert "title: kept" in result    # existing frontmatter survived (not dropped)
    assert "status: draft" in result  # new key merged


def test_merge_overrides_existing_key_value(vault_dir):
    """A new value for an existing key wins, while other keys keep their formatting."""
    path = "fmt.md"
    (config.VAULT_PATH / path).write_text(
        "---\nstatus: 'active'\ntags:\n  - alpha\n  - beta\n---\nbody\n"
    )

    vault_write(path, "---\nstatus: archived\n---\nbody\n",
                create_dirs=True, merge_frontmatter=True)

    result = (config.VAULT_PATH / path).read_text()
    assert "status: 'archived'" in result   # value overridden, quote slot kept
    assert "status: 'active'" not in result  # old value gone
    assert "  - alpha" in result             # untouched key keeps block style


def test_merge_bodyless_new_content_keeps_frontmatter(vault_dir):
    """New content with no frontmatter preserves existing frontmatter, replaces body."""
    path = "fmt.md"
    (config.VAULT_PATH / path).write_text(
        "---\ntitle: 'kept'\npinned: yes\n---\nold body\n"
    )

    vault_write(path, "brand new body only\n",
                create_dirs=True, merge_frontmatter=True)

    result = (config.VAULT_PATH / path).read_text()
    assert "title: 'kept'" in result
    assert "pinned: yes" in result
    assert "brand new body only" in result
    assert "old body" not in result


def test_no_merge_writes_content_byte_identical(vault_dir):
    """With merge_frontmatter=False the content is written verbatim (no YAML rewrite)."""
    path = "fmt.md"
    (config.VAULT_PATH / path).write_text("---\nold: 1\n---\nold body\n")

    content = "---\nstatus: yes\ntags: [a, b]\nq: 'x'\n---\nbody\n"
    vault_write(path, content, create_dirs=True, merge_frontmatter=False)

    assert (config.VAULT_PATH / path).read_text() == content


def test_merge_preserves_existing_key_order_and_appends_new(vault_dir):
    """A merge keeps existing keys in their original order and appends new keys after."""
    path = "fmt.md"
    (config.VAULT_PATH / path).write_text(
        "---\nalpha: 1\nbeta: 2\ngamma: 3\n---\nbody\n"
    )

    vault_write(path, "---\nbeta: 22\ndelta: 4\n---\nbody\n",
                create_dirs=True, merge_frontmatter=True)

    result = (config.VAULT_PATH / path).read_text()
    positions = [result.index(f"{key}:") for key in ("alpha", "beta", "gamma", "delta")]
    assert positions == sorted(positions)  # original order kept, new key appended last
    assert "beta: 22" in result            # overridden value applied in place
