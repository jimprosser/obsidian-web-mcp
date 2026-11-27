"""Core filesystem operations for the Obsidian vault."""

import fnmatch
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .content_extractors import apply_content_extractors
from .frontmatter_io import _is_fence


def _publish_mode(target: Path, tmp_fd: int) -> None:
    """Give the about-to-be-published temp file the mode a normal write would produce.

    tempfile.mkstemp() always creates its file 0600 (a temp-file security default),
    ignoring the process umask; that mode would otherwise survive the os.replace and
    silently downgrade every file the server writes -- breaking sync daemons / other
    readers and clobbering an existing note's permissions on each edit.

    Overwriting an existing file: keep that file's current mode (a write must not change
    permissions). New file: reproduce open()'s default, 0666 & ~umask. We fchmod the fd,
    not the path, so this can't be raced onto a symlinked target between here and replace.
    A no-op on platforms without fchmod (Windows), where mode bits are meaningless.
    """
    if not hasattr(os, "fchmod"):
        return
    try:
        mode = stat.S_IMODE(os.stat(target).st_mode)
    except FileNotFoundError:
        umask = os.umask(0)
        os.umask(umask)
        mode = 0o666 & ~umask
    os.fchmod(tmp_fd, mode)


def resolve_vault_path(relative_path: str) -> Path:
    """Resolve a relative path against the vault root, with safety checks.

    Raises ValueError if the path escapes the vault, contains null bytes,
    or touches dotfile/dot-directory components.
    """
    if "\x00" in relative_path:
        raise ValueError("Path contains null bytes")

    # Check for dot-prefixed components (blocks .obsidian, .trash, dotfiles)
    parts = Path(relative_path).parts
    for part in parts:
        if part.startswith("."):
            raise ValueError(
                f"Path component '{part}' starts with '.'; dotfiles and hidden directories are not allowed"
            )

    resolved = (config.VAULT_PATH / relative_path).resolve()
    vault_root = config.VAULT_PATH.resolve()

    if not str(resolved).startswith(str(vault_root) + os.sep) and resolved != vault_root:
        raise ValueError("Path resolves outside the vault root")

    return resolved


def resolve_vault_read_path(relative_path: str) -> Path:
    """Resolve a readable vault path; even legitimate in-vault hardlinks are unsupported.

    Raise ValueError on a security refusal, never a benign empty-read sentinel.
    """
    path = resolve_vault_path(relative_path)
    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {relative_path}")
    if path.stat().st_nlink > 1:
        raise ValueError(f"Refusing hardlinked file: {relative_path}")
    return path


def _iso_timestamp(ts: float) -> str:
    """Convert a Unix timestamp to an ISO 8601 string in UTC."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class BinaryFileTypeError(UnicodeDecodeError):
    """A file whose extension is on the binary allowlist, refused as text (#95).

    A UnicodeDecodeError on purpose: every caller already handles one as "not a text file",
    so a binary type is refused exactly the way an undecodable file is, whatever its bytes.
    """

    def __init__(self, relative_path: str, suffix: str):
        super().__init__("utf-8", b"", 0, 0, "binary file type")
        self.relative_path = relative_path
        self.suffix = suffix

    def __str__(self) -> str:
        return f"{self.relative_path} is a binary file ({self.suffix}), not text"


def binary_extensions() -> frozenset[str]:
    """Extensions decided as binary by name, never by content: those on the binary allowlist.

    A PDF whose bytes happen to be all ASCII decodes as UTF-8; judged by its bytes it was
    read as text and editable as text, which breaks its stream lengths and xref offsets.
    The binary write path already trusts the declared extension; reads and text writes
    follow the same rule. That includes the types an operator adds through
    VAULT_EXTRA_BINARY_MEDIA_TYPES_JSON: a .docx the binary write path accepts is binary
    here too, so a text write cannot replace it.
    """
    # Imported here: tools.write imports this module.
    from .tools.write import allowed_binary_media_types

    return frozenset(ext for extensions in allowed_binary_media_types().values() for ext in extensions)


def read_file(relative_path: str, *, extract: bool = False) -> tuple[str, dict]:
    """Read a file and return (content, metadata).

    Metadata keys: size (int), modified (ISO str), created (ISO str).

    extract: offer a file that is not valid UTF-8 to the registered content extractors
    (``content_extractors``). Only the read tools pass True. Every other caller reads in
    order to write back, and extracted text written back would replace the binary.
    """
    path = resolve_vault_read_path(relative_path)

    stat = path.stat()
    from_extractor = False
    try:
        suffix = path.suffix.lower()
        if suffix in binary_extensions():
            raise BinaryFileTypeError(relative_path, suffix)
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        extracted = apply_content_extractors(relative_path, path) if extract else None
        if extracted is None:
            raise
        content = extracted
        from_extractor = True

    metadata = {
        "size": stat.st_size,
        "modified": _iso_timestamp(stat.st_mtime),
        "created": _iso_timestamp(stat.st_birthtime if hasattr(stat, "st_birthtime") else stat.st_ctime),
    }
    if from_extractor:
        # Say so in the response: the content is not what the file holds. Without this a
        # model that gets the safe decode error from vault_edit can fall back to
        # vault_write and replace the file with the extracted text. Only set when an
        # extractor supplied the content, so an ordinary read is unchanged.
        metadata["extracted"] = True

    return content, metadata


def write_file_atomic(
    relative_path: str, content: str, create_dirs: bool = True, overwrite: bool = True
) -> tuple[bool, int]:
    """Write content to a file atomically.

    Returns (is_new_file, bytes_written). Writes to a tempfile in the same
    directory then puts it in place, so readers never see a partial write.
    With overwrite=False an existing file is never replaced, not even by a
    concurrent writer: see _place_atomic.
    """
    suffix = Path(relative_path).suffix.lower()
    if suffix in binary_extensions():
        # Text writes never create or replace a binary type, whatever the content: a PDF
        # replaced by its extracted text is gone (#95). Binary writes go through
        # write_bytes_atomic, which does not pass here.
        raise ValueError(
            f"{relative_path} is a binary file type ({suffix}); a text write cannot create or "
            "replace it. Use vault_write_binary or a signed upload."
        )
    encoded = content.encode("utf-8")
    if len(encoded) > config.MAX_CONTENT_SIZE:
        raise ValueError(
            f"Content size {len(encoded)} bytes exceeds limit of {config.MAX_CONTENT_SIZE} bytes"
        )
    is_new = _place_atomic(relative_path, lambda f: f.write(encoded), create_dirs, overwrite)
    return is_new, len(encoded)


def write_bytes_atomic(
    relative_path: str, content: bytes, create_dirs: bool = True, overwrite: bool = True
) -> tuple[bool, int]:
    """Write raw bytes to a file atomically.

    The binary counterpart of write_file_atomic: writes to a tempfile in the same
    directory then puts it in place, so readers never see a partial write.
    Returns (is_new_file, bytes_written).

    With overwrite=False the placement is a true no-clobber: it uses os.link, which fails
    atomically if the target already exists, closing the check-then-write race that a plain
    exists()-then-os.replace would leave open. With overwrite=True it os.replace()s.
    """
    if len(content) > config.MAX_BINARY_SIZE:
        raise ValueError(
            f"Content size {len(content)} bytes exceeds limit of {config.MAX_BINARY_SIZE} bytes"
        )
    is_new = _place_atomic(relative_path, lambda f: f.write(content), create_dirs, overwrite)
    return is_new, len(content)


def write_file_from_path_atomic(
    relative_path: str, source: Path, create_dirs: bool = True, overwrite: bool = True
) -> tuple[bool, int]:
    """Copy a file (e.g. a streamed upload in the staging dir) into the vault atomically.

    Same placement guarantees as write_bytes_atomic, without holding the content in
    memory. The source may sit on another filesystem, so it is copied into a temp file
    next to the target rather than renamed. The size limit is the caller's: the upload
    route enforces its own cap while streaming.
    """
    size = source.stat().st_size

    def fill(f):
        with open(source, "rb") as src:
            shutil.copyfileobj(src, f, 1024 * 1024)

    is_new = _place_atomic(relative_path, fill, create_dirs, overwrite)
    return is_new, size


def _place_atomic(relative_path: str, fill, create_dirs: bool, overwrite: bool) -> bool:
    """Fill a temp file next to the target, then replace or no-clobber link it into place."""
    path = resolve_vault_path(relative_path)
    is_new = not path.exists()

    if create_dirs:
        path.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temp file in the same directory, then put it in place atomically.
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            fill(f)
            _publish_mode(path, f.fileno())
        if overwrite:
            os.replace(tmp_path, path)
        else:
            # Atomic create: os.link fails if the target exists (no clobber, no race).
            try:
                os.link(tmp_path, path)
            except FileExistsError:
                raise FileExistsError(f"File already exists: {relative_path}")
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            is_new = True
    except BaseException:
        # Clean up the temp file on any failure (os.replace consumes it on success).
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return is_new


def check_move(source: str, destination: str, create_dirs: bool = True) -> tuple[Path, Path]:
    """Validate a move without making it, so a dry run refuses what the move would.

    Covers the move's own rules. A filesystem refusal (permissions, a file where a
    parent directory should be) still surfaces only when the move runs.
    Returns the resolved (source, destination).
    """
    src = resolve_vault_path(source)
    dst = resolve_vault_path(destination)

    if not src.exists():
        raise FileNotFoundError(f"Source does not exist: {source}")

    if dst.exists():
        raise FileExistsError(f"Destination already exists: {destination}")

    if src.is_dir() and src in dst.parents:
        raise ValueError(f"Cannot move a directory into itself: {source} -> {destination}")

    if not create_dirs and not dst.parent.is_dir():
        raise FileNotFoundError(f"Destination directory does not exist: {Path(destination).parent}")

    return src, dst


def move_path(
    source: str, destination: str, create_dirs: bool = True
) -> bool:
    """Move a file or directory from source to destination.

    Both paths are relative to the vault root. Raises if the destination
    already exists.
    """
    src, dst = check_move(source, destination, create_dirs)

    if create_dirs:
        dst.parent.mkdir(parents=True, exist_ok=True)

    shutil.move(str(src), str(dst))
    return True


def delete_path(relative_path: str) -> bool:
    """Soft-delete by moving the path into .trash/ at the vault root.

    Refuses to delete non-empty directories.
    """
    path = resolve_vault_path(relative_path)

    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {relative_path}")

    if path.is_dir() and any(path.iterdir()):
        raise ValueError(f"Refusing to delete non-empty directory: {relative_path}")

    trash_dir = config.VAULT_PATH.resolve() / ".trash"
    trash_dir.mkdir(exist_ok=True)

    dest = trash_dir / path.name

    # Avoid collisions in .trash by appending a timestamp
    if dest.exists():
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")
        dest = trash_dir / f"{path.stem}_{ts}{path.suffix}"

    shutil.move(str(path), str(dest))
    return True


def list_directory(
    relative_path: str,
    depth: int = 1,
    include_files: bool = True,
    include_dirs: bool = True,
    pattern: str | None = None,
) -> list[dict]:
    """List directory contents recursively up to *depth* levels.

    Returns a list of dicts with keys: name, path (relative to vault),
    type ("file" or "dir"), size, modified.
    """
    depth = min(depth, config.MAX_LIST_DEPTH)

    root = resolve_vault_path(relative_path)
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {relative_path}")

    vault_root = config.VAULT_PATH.resolve()
    results: list[dict] = []

    def _walk(dir_path: Path, current_depth: int) -> None:
        if current_depth > depth:
            return

        try:
            entries = sorted(dir_path.iterdir(), key=lambda p: p.name.lower())
        except PermissionError as exc:
            # An unreadable directory is not an empty directory. Propagate the
            # failure so remote clients can distinguish a TCC/permission issue
            # from a genuinely empty vault. Name the directory relative to the
            # vault, like the sibling errors do: the absolute path would hand the
            # client the server's filesystem layout (and, on iCloud, the account).
            rel = dir_path.relative_to(vault_root)
            where = "the vault root" if str(rel) == "." else str(rel)
            raise PermissionError(f"Permission denied listing directory: {where}") from exc

        for entry in entries:
            # Skip excluded directories at every level
            if entry.name in config.EXCLUDED_DIRS:
                continue

            is_dir = entry.is_dir()

            if is_dir and not include_dirs:
                # Still recurse even if we're not listing dirs
                _walk(entry, current_depth + 1)
                continue

            if not is_dir and not include_files:
                continue

            # Apply glob pattern filter
            if pattern and not fnmatch.fnmatch(entry.name, pattern):
                if is_dir:
                    _walk(entry, current_depth + 1)
                continue

            try:
                stat = entry.stat()
            except OSError:
                continue

            rel = str(entry.relative_to(vault_root))

            results.append({
                "name": entry.name,
                "path": rel,
                "type": "dir" if is_dir else "file",
                "size": stat.st_size,
                "modified": _iso_timestamp(stat.st_mtime),
            })

            if is_dir:
                _walk(entry, current_depth + 1)

    _walk(root, 1)
    return results


# --- Headings and sections of a Markdown note ---
#
# One reading of a note's headings, for everything that addresses part of a note by
# its heading: vault_read's heading and outline, and heading-scoped edits after them
# (#109). The rule is the one from the #109 review:
#
# - An ATX heading is 1 to 6 '#' after at most three spaces, then a space, a tab or
#   the end of the line. A closing run of '#' is dropped only after a space, so
#   "## C#" keeps its '#'.
# - Fenced code (``` or ~~~, closed by the same character repeated at least as many
#   times, with nothing after it but spaces) and the leading frontmatter hold no
#   headings. An unclosed fence runs to the end of the note; an opening '---' with no
#   closing line is not frontmatter.
# - A setext heading, a '===' (level 1) or '---' (level 2) line under a paragraph,
#   ends a section but is not a heading to read: it is not in the outline. Under a
#   list item, a block quote or a table, such a line is a thematic break instead.
# - Lines are split on '\n' only: str.splitlines() also splits on U+2028, form feed
#   and a few others, which would put a heading where Obsidian shows none. A CRLF
#   line's '\r' is ignored for matching and kept in the content.

_BOM = "\ufeff"
# Every pattern here is anchored and can't backtrack over a run of whitespace, so a line
# is read in time linear in its length: a note is untrusted input, and Python's re
# backtracks, so a pattern like "(.*?)[ \t]*" takes time quadratic in a crafted line.
_ATX_OPENING = re.compile(r" {0,3}(#{1,6})(?=[ \t]|$)")
# A fence may open on a list item's own line ("- ```bash"); its closer is then indented
# like the item's content, so the closer's indent is counted from the opening fence.
_FENCE_OPEN = re.compile(r"( {0,3}(?:(?:[-+*]|\d{1,9}[.)])[ \t]+)?)(`{3,}|~{3,})(.*)")
_FENCE_CLOSE = re.compile(r"( *)(`{3,}|~{3,})[ \t]*")
_SETEXT_UNDERLINE = re.compile(r" {0,3}(?:=+|-+)[ \t]*")
_THEMATIC_BREAK = re.compile(r" {0,3}(?:(?:\*[ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})")
_LIST_OR_QUOTE = re.compile(r" {0,3}(?:(?:[-+*]|\d{1,9}[.)])(?:[ \t]|$)|>)")
_TABLE_CELL = re.compile(r":?-+:?")
_ESCAPED = re.compile(r"\\.")
_INDENTED_CODE = re.compile(r"(?: {4}|\t| {1,3}\t)")


@dataclass(frozen=True)
class MarkdownSection:
    """An ATX heading and the section it opens.

    ``line`` and ``end_line`` are 1-based and inclusive, counted from the file's first
    line, frontmatter included, as ``grep -n`` counts them. ``start`` and ``end`` are
    character offsets: ``content[start:end]`` is the section from its heading line through
    the line before the next heading of the same or a higher level (or the end of the
    note), newline included, subsections included. ``heading`` is the line as written,
    without its indentation or trailing whitespace; ``path`` is the headings of the
    sections it sits in, outermost first, then its own.
    """

    line: int
    end_line: int
    level: int
    heading: str
    path: tuple[str, ...]
    start: int
    end: int


def parse_atx_heading(line: str) -> tuple[int, str] | None:
    """Return (level, text) for an ATX heading line, or None if the line isn't one.

    ``text`` is the heading as Obsidian shows it: no '#' markers, no closing run of
    '#', no surrounding spaces.
    """
    match = _ATX_OPENING.match(line)
    if match is None:
        return None
    text = line[match.end():].strip(" \t")
    # A closing run of '#' counts only when a space comes before it, or it is all there is.
    before = text.rstrip("#")
    if before != text and (not before or before[-1] in " \t"):
        text = before.rstrip(" \t")
    return len(match.group(1)), text


def _table_cells(row: str) -> list[str]:
    # An escaped pipe ("\|", as in a wiki link's alias, [[note\|alias]]) is part of a cell, not a border.
    row = _ESCAPED.sub("..", row.strip(" \t"))
    return row.removeprefix("|").removesuffix("|").split("|")


def _is_table_delimiter(line: str, header: str) -> bool:
    """A table's delimiter row under its header: cells of '-', each with an optional ':' at
    either end, split by '|', as many as the header has; with another count it is no table."""
    if "|" not in line:
        return False
    cells = _table_cells(line)
    return len(cells) == len(_table_cells(header)) and all(
        _TABLE_CELL.fullmatch(cell.strip(" \t")) for cell in cells
    )


def _frontmatter_end(lines: list[str]) -> int:
    """Index of the first line after the leading frontmatter, or 0 when there is none."""
    if lines and _is_fence(lines[0].removeprefix(_BOM)):
        for index in range(1, len(lines)):
            if _is_fence(lines[index]):
                return index + 1
    return 0


def markdown_lines(content: str) -> list[str]:
    """The note's lines, split on '\\n' only, without their newlines.

    A last line with no newline counts; the empty piece after a final newline doesn't.
    """
    lines = content.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def markdown_sections(content: str) -> list[MarkdownSection]:
    """Every ATX heading of a Markdown note, in order, with the section it opens."""
    lines = markdown_lines(content)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line) + 1)
    offsets[-1] = len(content)  # the last line may have no newline

    # (line index, level, heading as written); None for a setext heading, which ends
    # sections but opens none.
    marks: list[tuple[int, int, str | None]] = []
    fence: tuple[str, int, int] | None = None  # the open fence's character, length, closer's indent
    block = None  # None, "paragraph", or "other": a list item, block quote or table
    paragraph_start = 0
    for index in range(_frontmatter_end(lines), len(lines)):
        line = lines[index].removesuffix("\r")
        if index == 0:
            line = line.removeprefix(_BOM)
        if fence is not None:
            close = _FENCE_CLOSE.fullmatch(line)
            if (
                close and len(close.group(1)) <= fence[2]
                and close.group(2)[0] == fence[0] and len(close.group(2)) >= fence[1]
            ):
                fence = None
            continue
        opening = _FENCE_OPEN.fullmatch(line)
        if opening and not (opening.group(2)[0] == "`" and "`" in opening.group(3)):
            in_item = opening.group(1).strip(" \t") != ""
            fence = (opening.group(2)[0], len(opening.group(2)), len(opening.group(1)) + 3 if in_item else 3)
            block = None
            continue
        if not line.strip(" \t"):
            block = None
            continue
        atx = parse_atx_heading(line)
        if atx is not None:
            marks.append((index, atx[0], line.strip(" \t")))
            block = None
        elif block == "paragraph" and _SETEXT_UNDERLINE.fullmatch(line):
            marks.append((paragraph_start, 1 if "=" in line else 2, None))
            block = None
        elif _THEMATIC_BREAK.fullmatch(line):
            block = None
        elif _LIST_OR_QUOTE.match(line) or (
            block == "paragraph" and _is_table_delimiter(line, lines[index - 1].removesuffix("\r"))
        ):
            block = "other"
        elif block is None and not _INDENTED_CODE.match(line):
            block = "paragraph"
            paragraph_start = index

    # One pass over the marks: a mark closes every open section of the same or a deeper
    # level, so each section's end is known when the next such mark comes, and the open
    # ones, at most six deep, are the path of the next heading.
    ends: dict[int, int] = {}
    paths: dict[int, tuple[str, ...]] = {}
    open_marks: list[int] = []
    for position, (index, level, heading) in enumerate(marks):
        while open_marks and marks[open_marks[-1]][1] >= level:
            ends[open_marks.pop()] = index
        if heading is not None:
            paths[position] = tuple(marks[open_][2] for open_ in open_marks) + (heading,)
            open_marks.append(position)

    sections = []
    for position, (index, level, heading) in enumerate(marks):
        if heading is None:
            continue
        end = ends.get(position, len(lines))
        sections.append(MarkdownSection(
            line=index + 1, end_line=end, level=level, heading=heading, path=paths[position],
            start=offsets[index], end=offsets[end],
        ))
    return sections


def heading_key(heading: str) -> tuple[int, str]:
    """What a heading line is matched on: its level, and its text stripped of any whitespace,
    as the input model strips what a caller sends (a trailing no-break space included). The
    line is stripped before it is parsed, so a closing run of '#' before such a space is cut."""
    level, text = parse_atx_heading(heading.strip())
    return level, text.strip()


def _wanted(part: str) -> tuple[int | None, str]:
    part = part.strip()
    atx = parse_atx_heading(part)
    return (atx[0], atx[1].strip()) if atx is not None else (None, part)


def find_sections(sections: list[MarkdownSection], heading: str) -> list[MarkdownSection]:
    """The sections that ``heading`` names, in note order.

    ``heading`` is a heading as written ("## Setup": that level and text), its text
    alone ("Setup": that text at any level), or a path from a parent heading, its parts
    joined by " > " ("# Guide > ## Setup"), each part either way and each inside the one
    before, at any depth. A heading whose own text holds " > " is tried whole first, so
    one copied from the outline names itself. When a path matches several sections, the
    ones whose full path it names level by level win over those it reaches by skipping
    levels. Matching is a plain, case-sensitive comparison of strings.
    """
    keys: dict[int, tuple[int, str]] = {}  # each heading parsed once, however many paths hold it

    def matches(wanted: tuple[int | None, str], written: str) -> bool:
        key = keys.get(id(written))
        if key is None:
            key = keys[id(written)] = heading_key(written)
        return key[1] == wanted[1] and wanted[0] in (None, key[0])

    if " > " in heading:
        literal = _wanted(heading)
        whole = [s for s in sections if matches(literal, s.heading)]
        if whole:
            return whole

    wanted = [_wanted(part) for part in heading.split(" > ")]
    *outer, own = wanted

    def inside(path: tuple[str, ...]) -> bool:
        parents = iter(path)
        return all(any(matches(part, parent) for parent in parents) for part in outer)

    found = [s for s in sections if matches(own, s.heading) and inside(s.path[:-1])]
    if len(found) > 1 and outer:
        exact = [s for s in found if len(s.path) == len(wanted) and all(map(matches, wanted, s.path))]
        if exact:
            return exact
    return found
