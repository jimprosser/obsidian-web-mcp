"""Read tools for the Obsidian vault MCP server."""

import logging
from collections import Counter

import frontmatter

from ..config import MAX_HEADING_LENGTH, MAX_HEADING_MATCHES
from ..serialization import dumps
from ..vault import (
    find_sections,
    heading_key,
    markdown_lines,
    markdown_sections,
    read_file,
    resolve_vault_path,
)

logger = logging.getLogger(__name__)


def _parsed_frontmatter(content: str):
    try:
        post = frontmatter.loads(content)
        if post.metadata:
            return post.metadata
    except Exception:
        pass
    return None


def _is_markdown(path: str, metadata: dict) -> bool:
    # Extracted text (a PDF, say) has no headings of its own, whatever its name.
    return path.lower().endswith((".md", ".markdown")) and not metadata.get("extracted")


def _outline(sections) -> list[dict]:
    return [{"line": s.line, "heading": s.heading, "chars": s.end - s.start} for s in sections]


def _outline_reply(path: str, content: str, metadata: dict) -> dict:
    return {
        "path": path,
        "size": {"chars": len(content), "lines": len(markdown_lines(content))},
        "outline": _outline(markdown_sections(content)),
        "frontmatter": _parsed_frontmatter(content),
        "metadata": metadata,
    }


def _whole_body(path: str, content: str, metadata: dict) -> dict:
    return {
        "path": path,
        "content": content,
        "metadata": metadata,
        "frontmatter": _parsed_frontmatter(content),
    }


def _repeat_reply(path: str, sections, found) -> dict:
    """The error for a heading that names several sections: each match with the path that
    names it, at most MAX_HEADING_MATCHES of them, so a crafted note can't make it huge.

    A match's path names it alone unless another section has the same path, level by level,
    or, for a heading with no parent, the same heading anywhere; unless it is longer than
    heading takes; and unless one of its parts holds " > " itself. Each heading is parsed
    and searched once, by its identity, however many paths hold it.
    """
    keys: dict[int, tuple[int, str]] = {}
    separator: dict[int, bool] = {}

    def key(written: str) -> tuple[int, str]:
        if id(written) not in keys:
            keys[id(written)] = heading_key(written)
            separator[id(written)] = " > " in written
        return keys[id(written)]

    same_path = Counter(tuple(key(h) for h in s.path) for s in sections)
    same_heading = Counter(key(s.heading) for s in sections)
    matches = []
    told_apart = True
    for s in found:
        length = sum(len(h) for h in s.path) + len(" > ") * (len(s.path) - 1)
        if length > MAX_HEADING_LENGTH:
            alone = False
        elif len(s.path) == 1:
            alone = same_heading[key(s.heading)] == 1
        else:
            alone = same_path[tuple(key(h) for h in s.path)] == 1 and not any(separator[id(h)] for h in s.path)
        told_apart = told_apart and alone
        if len(matches) < MAX_HEADING_MATCHES:
            # A path too long to pass back is left out rather than sent.
            named = " > ".join(s.path) if length <= MAX_HEADING_LENGTH else None
            matches.append({"heading": named, "line": s.line, "chars": s.end - s.start})

    error = f"The heading matches {len(found)} sections; pass one of their headings from matches"
    if len(found) > MAX_HEADING_MATCHES:
        error += f" (the first {MAX_HEADING_MATCHES}), or a longer path"
    if not told_apart:
        error += ". Some of them no path tells apart: read the section above them, or the whole note"
    return {"error": error, "path": path, "matches": matches}


def _section_reply(path: str, content: str, metadata: dict, heading: str) -> dict:
    sections = markdown_sections(content)
    found = find_sections(sections, heading)
    if not found:
        if not sections:
            return {"error": "The note has no headings, so it has no sections to read", "path": path, "outline": []}
        outline = _outline(sections)
        if len(dumps(outline)) >= len(dumps(_whole_body(path, content, metadata))):
            # A note of little but headings: its outline would outweigh the note itself.
            return {
                "error": "No heading matches, and the outline would be bigger than the note: read the whole note",
                "path": path,
            }
        return {"error": "No heading matches; the outline lists the note's headings", "path": path, "outline": outline}
    if len(found) > 1:
        return _repeat_reply(path, sections, found)
    section = found[0]
    return {
        "path": path,
        "heading": " > ".join(section.path),
        "start_line": section.line,
        "end_line": section.end_line,
        "content": content[section.start:section.end],
        "metadata": metadata,
    }


def vault_read(path: str, heading: str | None = None, outline: bool = False) -> str:
    """Read a file from the vault, returning content, metadata, and parsed frontmatter.

    With ``heading``, only the section it names, its subheadings included; with
    ``outline``, the note's headings, each with its line and its section's size, instead
    of its content. Both only on a Markdown note.
    """
    try:
        resolved = resolve_vault_path(path)
        content, metadata = read_file(path, extract=True)

        if heading is not None or outline:
            if not _is_markdown(path, metadata):
                return dumps({"error": "Headings exist only in Markdown notes", "path": path})
            if outline:
                return dumps(_outline_reply(path, content, metadata))
            return dumps(_section_reply(path, content, metadata, heading))

        return dumps(_whole_body(path, content, metadata))
    except ValueError as e:
        return dumps({"error": str(e), "path": path})
    except FileNotFoundError:
        return dumps({"error": f"File not found: {path}", "path": path})
    except Exception as e:
        logger.error(f"vault_read error for {path}: {e}")
        return dumps({"error": str(e), "path": path})


def vault_batch_read(paths: list[str], include_content: bool = True) -> str:
    """Read multiple files from the vault in one call."""
    results = []
    found = 0
    missing = 0

    for path in paths:
        try:
            content, metadata = read_file(path, extract=True)

            fm_data = None
            try:
                post = frontmatter.loads(content)
                if post.metadata:
                    fm_data = post.metadata
            except Exception:
                pass

            entry = {
                "path": path,
                "metadata": metadata,
                "frontmatter": fm_data,
            }
            if include_content:
                entry["content"] = content

            results.append(entry)
            found += 1
        except (ValueError, FileNotFoundError) as e:
            results.append({"path": path, "error": str(e)})
            missing += 1
        except Exception as e:
            results.append({"path": path, "error": str(e)})
            missing += 1

    return dumps({"files": results, "found": found, "missing": missing})
