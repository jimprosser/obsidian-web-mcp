"""Search tools for the Obsidian vault MCP server."""

import json
import logging
import shutil
import subprocess
from pathlib import Path

import frontmatter

from .. import config
from ..content_extractors import DEFAULT_SEARCH_PATTERN, default_search_patterns
from ..serialization import dumps
from ..vault import resolve_vault_path, resolve_vault_read_path

logger = logging.getLogger(__name__)


def _search_ripgrep(
    query: str,
    search_path: Path,
    file_pattern: list[str] | str,
    max_results: int,
    context_lines: int,
) -> list[dict]:
    """Search using ripgrep for performance. file_pattern: one glob or several (any match)."""
    file_patterns = [file_pattern] if isinstance(file_pattern, str) else list(file_pattern)
    cmd = [
        "rg",
        "--json",
        f"--max-count={max_results}",
        *(f"--glob={pattern}" for pattern in file_patterns),
        "-i",
        f"--context={context_lines}",
    ]

    for excluded in config.EXCLUDED_DIRS:
        cmd.append(f"--glob=!{excluded}/")

    # Pass the user-supplied query with `-e` so a value beginning with "-"
    # (e.g. "--pre=/bin/sh", a ripgrep preprocessor flag that executes an
    # arbitrary program per searched file) is parsed as a SEARCH PATTERN, not
    # as a ripgrep option. Appending it bare here was an argv option-injection
    # that allowed remote code execution via the vault_search query argument.
    cmd += ["-e", query, str(search_path)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    # ripgrep streams one event per line: "begin", then "context" and "match" events,
    # then "end". A match's trailing context arrives after the match event, so the
    # block cannot be assembled while streaming: collect the lines rg emitted per file,
    # then cut each match's window out of them. Before this, every "context" event was
    # dropped and match_context held the bare matching line, while _search_python
    # returned the surrounding lines (#39).
    emitted: dict[str, dict[int, str]] = {}
    hits: list[tuple[str, int]] = []

    for line in result.stdout.splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        if data.get("type") not in ("match", "context"):
            continue
        event = data["data"]
        line_number = event.get("line_number")
        # A hit in a binary file carries {"bytes": ...} and no usable line: skip it.
        line_text = event.get("lines", {}).get("text")
        if line_number is None or line_text is None:
            continue
        file_path = event["path"]["text"]
        # "\r\n" too: _search_python splits with str.splitlines, which drops both.
        emitted.setdefault(file_path, {})[line_number] = line_text.rstrip("\r\n")
        if data["type"] == "match":
            hits.append((file_path, line_number))

    matches = []

    for file_path, line_number in hits:
        try:
            rel_path = str(Path(file_path).relative_to(config.VAULT_PATH))
            # rg has already read the bytes. A refusal must discard its match,
            # not fall back to the line in the JSON event.
            resolve_vault_read_path(rel_path)
        except (ValueError, OSError):
            continue

        # The same window as _search_python's lines[i - n : i + n + 1]. Neighbours that
        # don't exist (start or end of the file) are left out, not padded.
        lines = emitted[file_path]
        window = [lines[n] for n in range(line_number - context_lines, line_number + context_lines + 1) if n in lines]

        matches.append({
            "path": rel_path,
            "line_number": line_number,
            "match_context": "\n".join(window),
        })

        if len(matches) >= max_results:
            break

    return matches


def _iter_vault_files(search_path: Path, file_pattern: list[str] | str):
    """Yield files under search_path, honoring EXCLUDED_DIRS and the glob pattern(s).

    file_pattern is one glob or several; a file matching any of them is yielded.

    Excluded and dot-prefixed directories are pruned without descending into
    them (a vault's .git can dwarf the vault itself), and symlinks are never
    followed -- the same rule resolve_vault_path enforces on reads, applied
    here so the walk cannot surface a name it would refuse to open.
    """
    import fnmatch
    import os

    file_patterns = [file_pattern] if isinstance(file_pattern, str) else list(file_pattern)

    def walk(directory):
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError:
            return
        for entry in entries:
            if entry.name.startswith(".") or entry.name in config.EXCLUDED_DIRS:
                continue
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                yield from walk(entry.path)
            elif entry.is_file(follow_symlinks=False) and any(
                fnmatch.fnmatch(entry.name, pattern) for pattern in file_patterns
            ):
                yield Path(entry.path)

    yield from walk(search_path)


def _search_python(
    query: str,
    search_path: Path,
    file_pattern: list[str] | str,
    max_results: int,
    context_lines: int,
) -> list[dict]:
    """Fallback Python-based search. file_pattern: one glob or several (any match)."""
    query_lower = query.lower()
    matches = []

    for file_path in _iter_vault_files(search_path, file_pattern):
        try:
            rel_path = str(file_path.relative_to(config.VAULT_PATH))
            safe_path = resolve_vault_read_path(rel_path)
            content = safe_path.read_text(encoding="utf-8")
        except (ValueError, OSError):
            continue

        lines = content.splitlines()
        for i, line in enumerate(lines):
            if query_lower in line.lower():
                start = max(0, i - context_lines)
                end = min(len(lines), i + context_lines + 1)
                context = "\n".join(lines[start:end])

                matches.append({
                    "path": rel_path,
                    "line_number": i + 1,
                    "match_context": context,
                })

                if len(matches) >= max_results:
                    return matches

    return matches


def _search_filenames(
    query: str,
    search_path: Path,
    file_pattern: str,
    max_results: int,
) -> list[dict]:
    """Match the query against vault-relative file paths (case-insensitive)."""
    query_lower = query.lower()
    matches = []

    for file_path in _iter_vault_files(search_path, file_pattern):
        try:
            rel_path = str(file_path.relative_to(config.VAULT_PATH))
        except ValueError:
            continue

        if query_lower in rel_path.lower():
            matches.append({
                "path": rel_path,
                "line_number": None,
                "match_context": rel_path,
                "match_type": "filename",
            })

            if len(matches) >= max_results:
                break

    return matches


def _get_frontmatter_excerpt(file_path: Path, max_keys: int = 3) -> dict | None:
    """Read frontmatter from a file, returning first N key-value pairs."""
    try:
        rel_path = str(file_path.relative_to(config.VAULT_PATH))
        safe_path = resolve_vault_read_path(rel_path)
        content = safe_path.read_text(encoding="utf-8")
        post = frontmatter.loads(content)
        if not post.metadata:
            return None
        keys = list(post.metadata.keys())[:max_keys]
        return {k: post.metadata[k] for k in keys}
    except Exception:
        return None


def vault_search(
    query: str,
    path_prefix: str | None = None,
    file_pattern: str | None = None,
    max_results: int = 20,
    context_lines: int = 2,
) -> str:
    """Search for text across vault file names and contents.

    file_pattern=None means the default. Contents: notes plus the patterns extensions
    registered (content_extractors.register_search_pattern). Names: notes only, because a
    registered pattern usually names a derivative of a vault file (an OCR sidecar,
    "scan.pdf.ocr.txt"), and matching those names would return a note and its sidecar
    for every name query. An explicit file_pattern is used as given for both.
    """
    if file_pattern is not None:
        content_patterns, name_pattern = [file_pattern], file_pattern
    else:
        content_patterns, name_pattern = default_search_patterns(), DEFAULT_SEARCH_PATTERN
    try:
        if path_prefix:
            search_path = resolve_vault_path(path_prefix)
        else:
            search_path = config.VAULT_PATH

        if not search_path.is_dir():
            return dumps({"error": f"Search path is not a directory: {path_prefix}"})

        name_candidates = _search_filenames(query, search_path, name_pattern, max_results)

        # Content matches keep a guaranteed share of the budget: a query that
        # is also a folder or date token can match many names, and those must
        # not starve the body hits clients relied on before name matching.
        content_budget = max_results - min(len(name_candidates), max_results // 2)
        if shutil.which("rg"):
            content_matches = _search_ripgrep(query, search_path, content_patterns, content_budget, context_lines)
        else:
            content_matches = _search_python(query, search_path, content_patterns, content_budget, context_lines)

        # Only content hits get the frontmatter excerpt. Name-only hits are
        # never read at all: the path locates the note, and reading it would
        # be both an unbounded cost and a disclosure the walk already refuses.
        for match in content_matches:
            match["match_type"] = "content"
            file_full_path = config.VAULT_PATH / match["path"]
            match["frontmatter_excerpt"] = _get_frontmatter_excerpt(file_full_path)

        # A file that also matched on content appears once, as the content
        # match (it carries the line and context). Budget content did not use
        # is backfilled with further name hits.
        content_paths = {match["path"] for match in content_matches}
        name_matches = [m for m in name_candidates if m["path"] not in content_paths]
        name_matches = name_matches[: max_results - len(content_matches)]

        matches = name_matches + content_matches

        truncated = len(matches) >= max_results

        return dumps({
            "results": matches,
            "total_matches": len(matches),
            "truncated": truncated,
        })
    except ValueError as e:
        return dumps({"error": str(e)})
    except Exception as e:
        logger.error(f"vault_search error: {e}")
        return dumps({"error": str(e)})


def vault_search_frontmatter(
    field: str,
    value: str = "",
    match_type: str = "exact",
    path_prefix: str | None = None,
    max_results: int = 20,
) -> str:
    """Search vault files by frontmatter field values using the in-memory index."""
    from ..server import frontmatter_index

    try:
        results = frontmatter_index.search_by_field(
            field=field,
            value=value,
            match_type=match_type,
            path_prefix=path_prefix,
        )

        formatted = []
        for item in results[:max_results]:
            path = item["path"]
            fm = item["frontmatter"]
            title = fm.get("title", Path(path).stem)
            formatted.append({
                "path": path,
                "frontmatter": fm,
                "title": title,
            })

        truncated = len(results) > max_results

        return dumps({
            "results": formatted,
            "total": len(formatted),
            "truncated": truncated,
        })
    except Exception as e:
        logger.error(f"vault_search_frontmatter error: {e}")
        return dumps({"error": str(e)})
