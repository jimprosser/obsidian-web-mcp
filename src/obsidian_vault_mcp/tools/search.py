"""Search tools for the Obsidian vault MCP server."""

import base64
import json
import logging
import shutil
import subprocess
from pathlib import Path

import frontmatter

from .. import config
from ..serialization import dumps
from ..vault import resolve_vault_path

logger = logging.getLogger(__name__)


def _split_lines(text: str) -> list[str]:
    """Split text into lines the way ripgrep counts them: on "\\n" only.

    Python's str.splitlines() also breaks on other separators (NEL, LINE and
    PARAGRAPH SEPARATOR, vertical tab, form feed, lone carriage return), which
    would desync the line index from ripgrep's "\\n"-based line_number. A
    trailing carriage return is stripped per line so CRLF files read the same as
    str.splitlines(), and a final empty element from a trailing newline is
    dropped. Both backends use this so their line numbering stays identical.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def _rg_match_line(match_data: dict) -> str:
    """Return ripgrep's matched line text, decoding base64 bytes if needed.

    ripgrep emits "bytes" instead of "text" when the matched line is not valid
    UTF-8; decode it lossily so the fallback never produces an empty snippet.
    """
    line = match_data["lines"]
    text = line.get("text")
    if text is None:
        encoded = line.get("bytes")
        text = (
            base64.b64decode(encoded).decode("utf-8", errors="replace")
            if encoded
            else ""
        )
    return text.rstrip("\n")


def _assemble_context(
    file_lines: list[str], match_index: int, context_lines: int
) -> str:
    """Return the matched line plus up to context_lines lines on each side.

    match_index is the 0-based index of the matched line. The slice is clamped
    at the file boundaries. Both search backends share this helper so they
    produce identical match_context for the same query, except when the ripgrep
    backend cannot re-read a matched file and degrades to the matched line only.
    """
    start = max(0, match_index - context_lines)
    end = min(len(file_lines), match_index + context_lines + 1)
    return "\n".join(file_lines[start:end])


def _search_ripgrep(
    query: str,
    search_path: Path,
    file_pattern: str,
    max_results: int,
    context_lines: int,
) -> list[dict]:
    """Search using ripgrep for performance."""
    cmd = [
        "rg",
        "--json",
        f"--max-count={max_results}",
        f"--glob={file_pattern}",
        "-i",
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

    matches = []
    # Cache each matched file's lines so multiple matches in one file read it
    # once. None means the file could not be re-read; in that case we degrade to
    # the matched line that ripgrep already gave us, with no surrounding context.
    file_lines_cache: dict[str, list[str] | None] = {}

    for line in result.stdout.splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        if data.get("type") == "match":
            match_data = data["data"]
            file_path = match_data["path"]["text"]
            try:
                rel_path = str(Path(file_path).relative_to(config.VAULT_PATH))
            except ValueError:
                continue

            line_number = match_data["line_number"]

            if file_path not in file_lines_cache:
                try:
                    # read_bytes, not read_text: text mode translates lone "\r"
                    # to "\n", which would desync _split_lines from rg's count.
                    file_lines_cache[file_path] = _split_lines(
                        Path(file_path).read_bytes().decode("utf-8")
                    )
                except (OSError, UnicodeDecodeError) as exc:
                    logger.warning(
                        "vault_search: could not re-read %s for context, "
                        "falling back to matched line only (%s)",
                        file_path,
                        exc,
                    )
                    file_lines_cache[file_path] = None

            file_lines = file_lines_cache[file_path]
            if file_lines is not None:
                match_context = _assemble_context(
                    file_lines, line_number - 1, context_lines
                )
            else:
                match_context = _rg_match_line(match_data)

            matches.append({
                "path": rel_path,
                "line_number": line_number,
                "match_context": match_context,
            })

            if len(matches) >= max_results:
                break

    return matches


def _search_python(
    query: str,
    search_path: Path,
    file_pattern: str,
    max_results: int,
    context_lines: int,
) -> list[dict]:
    """Fallback Python-based search."""
    import fnmatch

    query_lower = query.lower()
    matches = []

    for file_path in search_path.rglob("*"):
        if not file_path.is_file():
            continue

        if any(part in config.EXCLUDED_DIRS for part in file_path.parts):
            continue

        if not fnmatch.fnmatch(file_path.name, file_pattern):
            continue

        try:
            # read_bytes, not read_text: avoid universal-newline translation so
            # _split_lines counts lines the same way as the ripgrep backend.
            content = file_path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        lines = _split_lines(content)
        for i, line in enumerate(lines):
            if query_lower in line.lower():
                try:
                    rel_path = str(file_path.relative_to(config.VAULT_PATH))
                except ValueError:
                    continue

                matches.append({
                    "path": rel_path,
                    "line_number": i + 1,
                    "match_context": _assemble_context(lines, i, context_lines),
                })

                if len(matches) >= max_results:
                    return matches

    return matches


def _get_frontmatter_excerpt(file_path: Path, max_keys: int = 3) -> dict | None:
    """Read frontmatter from a file, returning first N key-value pairs."""
    try:
        content = file_path.read_text(encoding="utf-8")
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
    file_pattern: str = "*.md",
    max_results: int = 20,
    context_lines: int = 2,
) -> str:
    """Search for text across vault files."""
    try:
        if path_prefix:
            search_path = resolve_vault_path(path_prefix)
        else:
            search_path = config.VAULT_PATH

        if not search_path.is_dir():
            return dumps({"error": f"Search path is not a directory: {path_prefix}"})

        if shutil.which("rg"):
            matches = _search_ripgrep(query, search_path, file_pattern, max_results, context_lines)
        else:
            matches = _search_python(query, search_path, file_pattern, max_results, context_lines)

        for match in matches:
            file_full_path = config.VAULT_PATH / match["path"]
            match["frontmatter_excerpt"] = _get_frontmatter_excerpt(file_full_path)

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
