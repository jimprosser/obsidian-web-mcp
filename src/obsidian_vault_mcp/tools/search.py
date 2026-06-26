"""Search tools for the Obsidian vault MCP server."""

import base64
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

try:
    import fcntl  # POSIX only; used for the fd->path re-validation below
except ImportError:  # pragma: no cover - Windows
    fcntl = None

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


def _open_in_vault_nofollow(vault_root: Path, rel_path: str) -> int:
    """Open vault_root/rel_path for reading without following a symlink in any
    path component below the (trusted, configured) vault root.

    The matched path comes back from a separate ripgrep process and is opened in
    a later syscall, so a single path-based open is a TOCTOU: a symlink swapped
    into an intermediate component between a containment check and the open would
    be followed. Here each component under the root is opened with O_NOFOLLOW
    relative to its parent's directory fd (openat), so a symlink anywhere (final
    or intermediate, even one swapped in concurrently) fails the open atomically
    rather than being resolved by a racy path lookup. The configured root itself
    is opened normally, since it is allowed to be a symlink (VAULT_PATH may point
    at, e.g., a mounted volume).

    Where openat/dir_fd is unavailable (e.g. Windows) this degrades to a single
    O_NOFOLLOW open on the joined path, guarded by a (racy) resolved-path
    containment check. Raises OSError on any refusal so the caller degrades to
    ripgrep's matched line.
    """
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    parts = [p for p in Path(rel_path).parts if p not in ("", os.curdir)]

    if os.open not in os.supports_dir_fd or not parts:
        full = os.path.join(str(vault_root), rel_path)
        resolved = os.path.realpath(full)
        root = os.path.realpath(str(vault_root))
        if resolved != root and not resolved.startswith(root + os.sep):
            raise OSError("matched path resolves outside the vault")
        return os.open(full, os.O_RDONLY | nofollow)

    dir_fd = os.open(str(vault_root), os.O_RDONLY | directory)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | nofollow | directory, dir_fd=dir_fd)
            # Reassign before closing so an interrupted close (EINTR) leaves the
            # finally clause closing the fd we actually still hold, not a stale one.
            old_fd, dir_fd = dir_fd, next_fd
            os.close(old_fd)
        return os.open(parts[-1], os.O_RDONLY | nofollow, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


def _fd_resolves_inside_vault(fd: int, vault_root: Path) -> bool:
    """Re-validate that an opened fd refers to a path inside the vault root.

    Independent of the name used to open it, via the OS fd->path facility
    (F_GETPATH on macOS, /proc/self/fd on Linux). This is defense in depth behind
    the openat O_NOFOLLOW walk: if neither facility exists the openat chain and
    the resolve_vault_path gate are already the guarantee, so this returns True
    rather than failing closed where it cannot look the path up.
    """
    real = None
    if fcntl is not None and hasattr(fcntl, "F_GETPATH"):
        try:
            buf = fcntl.fcntl(fd, fcntl.F_GETPATH, b"\x00" * 1024)
            real = os.fsdecode(buf.split(b"\x00", 1)[0])
        except OSError:
            real = None
    if real is None:
        try:
            real = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            return True  # no fd->path lookup on this platform; rely on openat + gate
    real = os.path.realpath(real)
    root = os.path.realpath(str(vault_root))
    return real == root or real.startswith(root + os.sep)


def _safe_read_vault_bytes(rel_path: str, *, max_bytes: int | None = None) -> bytes | None:
    """Read a vault file's bytes, refusing unsafe reads (fail closed -> None).

    Shared by every path that reads a vault file off a name reported elsewhere:
    the ripgrep context re-read, the Python search fallback, and the per-result
    frontmatter excerpt. Guards, in order:
      * lexical: resolve_vault_path rejects null bytes, dotfile components, ".."
        traversal, and any target that resolves outside the vault root. openat
        with O_NOFOLLOW does NOT stop a ".." component (a real directory entry
        that walks up out of the vault), so this gate is what closes that escape.
      * symlink: each component below the root is opened O_NOFOLLOW via openat
        (see _open_in_vault_nofollow), so a symlink anywhere (final or
        intermediate, even swapped in concurrently) is refused, not followed.
      * resolved target: the opened fd is re-validated as inside the vault via
        the OS fd->path facility (see _fd_resolves_inside_vault), defense in
        depth behind the openat walk.
      * hardlink: a file with st_nlink > 1 is refused, because an in-vault
        hardlink to an outside file is a real directory entry the path and
        symlink checks cannot tell from a normal note (issue #53). Legitimate
        in-vault hardlinks are unsupported as a result.
      * size: when max_bytes is set, a larger file is refused to bound memory.
    """
    try:
        resolve_vault_path(rel_path)
    except ValueError:
        return None
    try:
        fd = _open_in_vault_nofollow(config.VAULT_PATH, rel_path)
        try:
            if not _fd_resolves_inside_vault(fd, config.VAULT_PATH):
                raise OSError("opened file resolves outside the vault")
            st = os.fstat(fd)
            if st.st_nlink > 1:
                raise OSError("refusing hardlinked file; in-vault hardlinks unsupported")
            if max_bytes is not None and st.st_size > max_bytes:
                raise OSError("file too large to read safely")
            chunks = []
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                chunks.append(block)
        finally:
            os.close(fd)
        return b"".join(chunks)
    except OSError as exc:
        logger.warning("vault_search: refusing unsafe read of %s (%s)", rel_path, exc)
        return None


def _read_vault_file_lines(rel_path: str) -> list[str] | None:
    """Re-read a ripgrep-matched vault file for context, refusing unsafe reads.

    rel_path is the match's path relative to the vault root. Returns the file's
    lines (per _split_lines), or None if the file cannot be read safely, in which
    case the caller degrades to ripgrep's matched line. See _safe_read_vault_bytes
    for the symlink / parent-traversal / hardlink guards; the size cap matters
    here because the whole file is read to slice context.
    """
    raw = _safe_read_vault_bytes(rel_path, max_bytes=config.MAX_SEARCH_REREAD_BYTES)
    if raw is None:
        return None
    try:
        # read_bytes-equivalent, not read_text: text mode translates lone "\r"
        # to "\n", which would desync _split_lines from rg's line count.
        return _split_lines(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


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
                file_lines_cache[file_path] = _read_vault_file_lines(rel_path)

            file_lines = file_lines_cache[file_path]
            match_index = line_number - 1
            # Degrade to ripgrep's matched line when the re-read was refused
            # (file_lines is None) or when rg's line_number is past the file's
            # current length -- a content race where the file shrank between rg's
            # scan and the re-read -- which would otherwise slice to an empty
            # snippet instead of the matched line.
            if file_lines is not None and 0 <= match_index < len(file_lines):
                match_context = _assemble_context(
                    file_lines, match_index, context_lines
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
            rel_path = str(file_path.relative_to(config.VAULT_PATH))
        except ValueError:
            continue

        # Same safe-read as the ripgrep backend: refuse a symlink out of the
        # vault and an in-vault hardlink to an outside file, so the fallback
        # cannot leak content the ripgrep path would not. No size cap here:
        # unlike the context re-read this read IS the search, and capping it
        # would silently drop matches in large files.
        raw = _safe_read_vault_bytes(rel_path)
        if raw is None:
            continue
        try:
            # read_bytes, not read_text: avoid universal-newline translation so
            # _split_lines counts lines the same way as the ripgrep backend.
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue

        lines = _split_lines(content)
        for i, line in enumerate(lines):
            if query_lower in line.lower():
                matches.append({
                    "path": rel_path,
                    "line_number": i + 1,
                    "match_context": _assemble_context(lines, i, context_lines),
                })

                if len(matches) >= max_results:
                    return matches

    return matches


def _get_frontmatter_excerpt(file_path: Path, max_keys: int = 3) -> dict | None:
    """Read frontmatter from a vault file, returning first N key-value pairs.

    Uses the same safe-read as the search backends (see _safe_read_vault_bytes)
    so attaching an excerpt to a result cannot follow a symlink out of the vault
    or read an in-vault hardlink to an outside file (issue #53).
    """
    try:
        rel_path = str(file_path.relative_to(config.VAULT_PATH))
    except ValueError:
        return None
    raw = _safe_read_vault_bytes(rel_path, max_bytes=config.MAX_SEARCH_REREAD_BYTES)
    if raw is None:
        return None
    try:
        post = frontmatter.loads(raw.decode("utf-8"))
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
