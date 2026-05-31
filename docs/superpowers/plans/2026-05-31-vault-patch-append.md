# vault_patch + vault_append Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two new MCP tools — `vault_patch` for surgical string replacement in vault files, and `vault_append` for appending content to vault files — eliminating the need to read-full + rewrite-full when editing large files.

**Architecture:** Both tools follow the existing pattern exactly: Pydantic input model in `models.py`, tool function in `tools/write.py`, `@mcp.tool` registration in `server.py`. `vault_patch` does a read-modify-write with strict match validation (fails on 0 or >1 matches unless `replace_all=True`). `vault_append` reads the existing content (or starts empty for new files) and writes `existing + separator + new_content` atomically.

**Tech Stack:** Python 3.14, Pydantic v2, FastMCP, pytest. All writes go through the existing `write_file_atomic` — atomic, UTF-8 encoded, size-limited.

---

## File Map

| Action | File | What changes |
|--------|------|--------------|
| Modify | `src/obsidian_vault_mcp/models.py` | Add `VaultPatchInput` and `VaultAppendInput` |
| Modify | `src/obsidian_vault_mcp/tools/write.py` | Add `vault_patch()` and `vault_append()` functions |
| Modify | `src/obsidian_vault_mcp/server.py` | Register the two new `@mcp.tool` decorators and update imports |
| Modify | `tests/test_tools.py` | Add tests for both tools |

---

## Task 1: vault_patch

### Files:
- Modify: `src/obsidian_vault_mcp/models.py`
- Modify: `src/obsidian_vault_mcp/tools/write.py`
- Modify: `src/obsidian_vault_mcp/server.py`
- Test: `tests/test_tools.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_tools.py` (after the last existing import, add `vault_patch` to the import line from `tools.write`; add these test functions at the bottom of the file):

```python
from obsidian_vault_mcp.tools.write import vault_write, vault_batch_frontmatter_update, vault_patch, vault_append
```

```python
# --- vault_patch tests ---

def test_vault_patch_replaces_unique_string(vault_dir):
    """vault_patch replaces a string that appears exactly once."""
    vault_write("patch-test.md", "# Title\n\nOld content here.\n\nMore text.")
    result = json.loads(vault_patch("patch-test.md", "Old content here.", "New content here."))
    assert "error" not in result
    assert result["replacements"] == 1
    read_result = json.loads(vault_read("patch-test.md"))
    assert "New content here." in read_result["content"]
    assert "Old content here." not in read_result["content"]


def test_vault_patch_fails_on_no_match(vault_dir):
    """vault_patch returns error when old_string is not found."""
    vault_write("patch-test2.md", "# Title\n\nSome content.")
    result = json.loads(vault_patch("patch-test2.md", "nonexistent string", "replacement"))
    assert "error" in result
    assert "0 occurrences" in result["error"]


def test_vault_patch_fails_on_multiple_matches(vault_dir):
    """vault_patch returns error when old_string appears more than once."""
    vault_write("patch-test3.md", "repeat repeat repeat")
    result = json.loads(vault_patch("patch-test3.md", "repeat", "once"))
    assert "error" in result
    assert "3 occurrences" in result["error"]


def test_vault_patch_replace_all(vault_dir):
    """vault_patch with replace_all=True replaces every occurrence."""
    vault_write("patch-test4.md", "a b a b a")
    result = json.loads(vault_patch("patch-test4.md", "a", "x", replace_all=True))
    assert "error" not in result
    assert result["replacements"] == 3
    read_result = json.loads(vault_read("patch-test4.md"))
    assert read_result["content"] == "x b x b x"


def test_vault_patch_file_not_found(vault_dir):
    """vault_patch returns error for nonexistent file."""
    result = json.loads(vault_patch("does-not-exist.md", "old", "new"))
    assert "error" in result
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/marcelotoledo/dev/obsidian-web-mcp
uv run pytest tests/test_tools.py -k "vault_patch" -v
```

Expected: `ImportError` or `FAILED` — `vault_patch` not defined yet.

- [ ] **Step 3: Add VaultPatchInput model**

In `src/obsidian_vault_mcp/models.py`, add after `VaultWriteInput` (around line 54):

```python
class VaultPatchInput(BaseModel):
    """Surgical string replacement in a vault file."""

    model_config = ConfigDict(str_strip_whitespace=False, extra="forbid")

    path: str = Field(
        ...,
        description="Relative path from vault root",
        min_length=1,
        max_length=500,
    )
    old_string: str = Field(
        ...,
        description="Exact string to find and replace",
        min_length=1,
        max_length=MAX_CONTENT_SIZE,
    )
    new_string: str = Field(
        ...,
        description="Replacement string",
        max_length=MAX_CONTENT_SIZE,
    )
    replace_all: bool = Field(
        default=False,
        description="If true, replace all occurrences; if false (default), fail unless exactly one occurrence exists",
    )
```

Note: `str_strip_whitespace=False` — patch strings must be matched verbatim, including leading/trailing whitespace.

- [ ] **Step 4: Add vault_patch function**

In `src/obsidian_vault_mcp/tools/write.py`, add after `vault_write` (around line 41):

```python
def vault_patch(path: str, old_string: str, new_string: str, replace_all: bool = False) -> str:
    """Replace a string in a vault file. Fails on 0 or >1 matches unless replace_all=True."""
    try:
        content, _ = read_file(path)
        count = content.count(old_string)

        if count == 0:
            return json.dumps({"error": f"0 occurrences of old_string found in '{path}'", "path": path})

        if count > 1 and not replace_all:
            return json.dumps({"error": f"{count} occurrences of old_string found in '{path}'; use replace_all=True to replace all", "path": path})

        new_content = content.replace(old_string, new_string)
        _, size = write_file_atomic(path, new_content, create_dirs=False)

        return json.dumps({"path": path, "replacements": count, "size": size})
    except FileNotFoundError:
        return json.dumps({"error": f"File not found: '{path}'", "path": path})
    except ValueError as e:
        return json.dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_patch error for {path}: {e}")
        return json.dumps({"error": str(e), "path": path})
```

- [ ] **Step 5: Run tests to verify vault_patch passes**

```bash
cd /Users/marcelotoledo/dev/obsidian-web-mcp
uv run pytest tests/test_tools.py -k "vault_patch" -v
```

Expected: all 5 `vault_patch` tests PASS.

- [ ] **Step 6: Register vault_patch in server.py**

In `src/obsidian_vault_mcp/server.py`:

Update the import from `tools.write` (line 50) to include `vault_patch`:
```python
from .tools.write import vault_write as _vault_write, vault_batch_frontmatter_update as _vault_batch_frontmatter_update, vault_patch as _vault_patch
```

Update the import from `.models` (around line 53–63) to include `VaultPatchInput`:
```python
from .models import (
    VaultReadInput,
    VaultWriteInput,
    VaultPatchInput,
    VaultBatchReadInput,
    VaultBatchFrontmatterUpdateInput,
    VaultSearchInput,
    VaultSearchFrontmatterInput,
    VaultListInput,
    VaultMoveInput,
    VaultDeleteInput,
)
```

Add the tool registration after the `vault_write` block (around line 97):
```python
@mcp.tool(
    name="vault_patch",
    description="Surgically replace a string in a vault file without rewriting the whole file. Fails if the string appears 0 or >1 times (use replace_all=True for multi-replace). Prefer this over vault_write when editing a section of a large file.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
)
def vault_patch(path: str, old_string: str, new_string: str, replace_all: bool = False) -> str:
    """Surgical string replacement in a vault file."""
    inp = VaultPatchInput(path=path, old_string=old_string, new_string=new_string, replace_all=replace_all)
    return _vault_patch(inp.path, inp.old_string, inp.new_string, inp.replace_all)
```

- [ ] **Step 7: Run full test suite**

```bash
cd /Users/marcelotoledo/dev/obsidian-web-mcp
uv run pytest tests/ -v
```

Expected: all tests PASS (no regressions).

- [ ] **Step 8: Commit**

```bash
git add src/obsidian_vault_mcp/models.py src/obsidian_vault_mcp/tools/write.py src/obsidian_vault_mcp/server.py tests/test_tools.py
git commit -m "feat: add vault_patch tool for surgical string replacement"
```

---

## Task 2: vault_append

### Files:
- Modify: `src/obsidian_vault_mcp/models.py`
- Modify: `src/obsidian_vault_mcp/tools/write.py`
- Modify: `src/obsidian_vault_mcp/server.py`
- Test: `tests/test_tools.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_tools.py` at the bottom:

```python
# --- vault_append tests ---

def test_vault_append_adds_to_existing(vault_dir):
    """vault_append adds content after existing file body."""
    vault_write("append-test.md", "# Log\n\nFirst entry.")
    result = json.loads(vault_append("append-test.md", "Second entry."))
    assert "error" not in result
    assert result["created"] is False
    read_result = json.loads(vault_read("append-test.md"))
    assert "First entry." in read_result["content"]
    assert "Second entry." in read_result["content"]
    assert read_result["content"].index("First entry.") < read_result["content"].index("Second entry.")


def test_vault_append_creates_new_file(vault_dir):
    """vault_append creates the file if it does not exist."""
    result = json.loads(vault_append("new-append.md", "Initial content."))
    assert "error" not in result
    assert result["created"] is True
    assert (vault_dir / "new-append.md").exists()
    read_result = json.loads(vault_read("new-append.md"))
    assert "Initial content." in read_result["content"]


def test_vault_append_custom_separator(vault_dir):
    """vault_append respects a custom separator."""
    vault_write("sep-test.md", "line one")
    result = json.loads(vault_append("sep-test.md", "line two", separator="\n\n---\n\n"))
    assert "error" not in result
    read_result = json.loads(vault_read("sep-test.md"))
    assert "line one\n\n---\n\nline two" in read_result["content"]


def test_vault_append_no_double_separator(vault_dir):
    """vault_append on a new file does not prepend the separator."""
    result = json.loads(vault_append("fresh.md", "content", separator="\n\n"))
    assert "error" not in result
    read_result = json.loads(vault_read("fresh.md"))
    assert read_result["content"] == "content"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/marcelotoledo/dev/obsidian-web-mcp
uv run pytest tests/test_tools.py -k "vault_append" -v
```

Expected: `ImportError` or `FAILED` — `vault_append` not defined yet.

- [ ] **Step 3: Add VaultAppendInput model**

In `src/obsidian_vault_mcp/models.py`, add after `VaultPatchInput`:

```python
class VaultAppendInput(BaseModel):
    """Append content to a vault file."""

    model_config = ConfigDict(str_strip_whitespace=False, extra="forbid")

    path: str = Field(
        ...,
        description="Relative path from vault root",
        min_length=1,
        max_length=500,
    )
    content: str = Field(
        ...,
        description="Content to append",
        min_length=1,
        max_length=MAX_CONTENT_SIZE,
    )
    separator: str = Field(
        default="\n",
        description="String inserted between existing content and new content. Default is a single newline. Ignored when the file does not exist yet.",
        max_length=100,
    )
```

- [ ] **Step 4: Add vault_append function**

In `src/obsidian_vault_mcp/tools/write.py`, add after `vault_patch`:

```python
def vault_append(path: str, content: str, separator: str = "\n") -> str:
    """Append content to a vault file, creating it if it doesn't exist."""
    try:
        resolve_vault_path(path)

        try:
            existing, _ = read_file(path)
            new_content = existing + separator + content
            is_new = False
        except FileNotFoundError:
            new_content = content
            is_new = True

        _, size = write_file_atomic(path, new_content, create_dirs=True)

        return json.dumps({"path": path, "created": is_new, "size": size})
    except ValueError as e:
        return json.dumps({"error": str(e), "path": path})
    except Exception as e:
        logger.error(f"vault_append error for {path}: {e}")
        return json.dumps({"error": str(e), "path": path})
```

Note: `resolve_vault_path` is called first (before `read_file`) so path validation happens even when the file doesn't exist yet.

- [ ] **Step 5: Run tests to verify vault_append passes**

```bash
cd /Users/marcelotoledo/dev/obsidian-web-mcp
uv run pytest tests/test_tools.py -k "vault_append" -v
```

Expected: all 4 `vault_append` tests PASS.

- [ ] **Step 6: Register vault_append in server.py**

Update the import from `tools.write` to include `vault_append`:
```python
from .tools.write import vault_write as _vault_write, vault_batch_frontmatter_update as _vault_batch_frontmatter_update, vault_patch as _vault_patch, vault_append as _vault_append
```

Update the import from `.models` to include `VaultAppendInput`:
```python
from .models import (
    VaultReadInput,
    VaultWriteInput,
    VaultPatchInput,
    VaultAppendInput,
    VaultBatchReadInput,
    VaultBatchFrontmatterUpdateInput,
    VaultSearchInput,
    VaultSearchFrontmatterInput,
    VaultListInput,
    VaultMoveInput,
    VaultDeleteInput,
)
```

Add the tool registration after the `vault_patch` block:
```python
@mcp.tool(
    name="vault_append",
    description="Append content to a vault file without reading the whole file first. Creates the file if it doesn't exist. Use for adding log entries, session notes, or new sections to the end of a file.",
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
)
def vault_append(path: str, content: str, separator: str = "\n") -> str:
    """Append content to a vault file."""
    inp = VaultAppendInput(path=path, content=content, separator=separator)
    return _vault_append(inp.path, inp.content, inp.separator)
```

- [ ] **Step 7: Run full test suite**

```bash
cd /Users/marcelotoledo/dev/obsidian-web-mcp
uv run pytest tests/ -v
```

Expected: all tests PASS (no regressions).

- [ ] **Step 8: Commit**

```bash
git add src/obsidian_vault_mcp/models.py src/obsidian_vault_mcp/tools/write.py src/obsidian_vault_mcp/server.py tests/test_tools.py
git commit -m "feat: add vault_append tool for appending content to vault files"
```

---

## Self-Review

**Spec coverage:**
- `vault_patch` with unique match ✓ (Task 1, test_vault_patch_replaces_unique_string)
- `vault_patch` error on 0 matches ✓ (test_vault_patch_fails_on_no_match)
- `vault_patch` error on >1 matches ✓ (test_vault_patch_fails_on_multiple_matches)
- `vault_patch` replace_all ✓ (test_vault_patch_replace_all)
- `vault_patch` file not found ✓ (test_vault_patch_file_not_found)
- `vault_append` on existing file ✓ (test_vault_append_adds_to_existing)
- `vault_append` creates new file ✓ (test_vault_append_creates_new_file)
- `vault_append` custom separator ✓ (test_vault_append_custom_separator)
- `vault_append` no separator prepended on new file ✓ (test_vault_append_no_double_separator)
- Server registration for both tools ✓ (Tasks 1 + 2, Step 6)

**Placeholder scan:** no TBDs, no "similar to Task N", all code blocks are complete.

**Type consistency:** `vault_patch(path, old_string, new_string, replace_all)` and `VaultPatchInput` match throughout. `vault_append(path, content, separator)` and `VaultAppendInput` match throughout. `_vault_patch` / `_vault_append` aliases match the function names.
