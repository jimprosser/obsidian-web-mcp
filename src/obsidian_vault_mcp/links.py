"""Rewrite the links that point at a note when that note is moved or renamed.

Obsidian itself repoints every reference when you rename a note in the app; a
``vault_move`` over MCP is a plain filesystem move, so without this the vault is
left holding links that no longer resolve. That asymmetry is the whole reason
this module exists: the same operation should not mean two different things
depending on which client performed it.

Scope is deliberately narrow. Only these two forms are rewritten, in ``.md``
files:

- wikilinks and embeds -- ``[[target]]``, ``[[target|alias]]``,
  ``[[target#heading]]``, ``[[target#^block]]``, ``![[target]]``
- markdown links whose target is a vault-relative path to the moved file --
  ``[text](folder/Note.md)``, percent-encoding included

A **bare-basename** wikilink (``[[Shed]]``) is only touched when that basename is
unique in the vault. Obsidian resolves an ambiguous basename by proximity to the
linking note, and guessing wrong would silently repoint a link at a different
note -- worse than leaving it alone. Ambiguous cases are reported back to the
caller instead, so a human can look.
"""

import logging
import re
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote, unquote

from . import config
from .tools.write import _unified_diff
from .vault import resolve_vault_read_path, write_file_atomic

logger = logging.getLogger(__name__)

# [[target]], [[target|alias]], ![[target#heading]]. The target runs up to the
# first '|' or '#'; both tails are preserved verbatim on rewrite.
_WIKILINK = re.compile(r"(?P<embed>!?)\[\[(?P<target>[^\[\]|#\n]*)(?P<tail>[^\[\]\n]*)\]\]")

# [text](url). Excludes <...> angle-bracket targets and anything with a scheme,
# which are handled as "not a vault path" below.
_MDLINK = re.compile(r"(?P<embed>!?)\[(?P<text>[^\]\n]*)\]\((?P<url>[^)\s\n]+)\)")

_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def _is_excluded(rel_parts: tuple[str, ...]) -> bool:
    return bool(config.EXCLUDED_DIRS & set(rel_parts))


def _iter_markdown_files():
    """Every .md file in the vault, skipping excluded and dot directories."""
    for path in config.VAULT_PATH.rglob("*.md"):
        rel = path.relative_to(config.VAULT_PATH)
        if _is_excluded(rel.parts) or any(p.startswith(".") for p in rel.parts):
            continue
        yield path, str(rel)


def _strip_md(rel_path: str) -> str:
    return rel_path[:-3] if rel_path.endswith(".md") else rel_path


def _basename_counts(pairs: list[tuple[str, str]], *, before_move: bool = False) -> dict[str, int]:
    """How many notes shared each basename BEFORE the move, for the ambiguity check.

    The move has already landed by the time we run, so counting the vault as it is
    now would miss the very collision we are guarding against: rename one of two
    `meeting.md` notes and the survivor looks unique. Undoing each pair restores
    the pre-move picture. A dry run counts before the move, so there is nothing to undo.
    """
    counts: dict[str, int] = {}
    for _, rel in _iter_markdown_files():
        stem = Path(rel).stem.lower()
        counts[stem] = counts.get(stem, 0) + 1
    if before_move:
        return counts
    for old, new in pairs:
        new_stem = Path(new).stem.lower()
        old_stem = Path(old).stem.lower()
        counts[new_stem] = counts.get(new_stem, 1) - 1
        counts[old_stem] = counts.get(old_stem, 0) + 1
    return counts


def _normalize_target(target: str) -> str:
    """A wikilink target, comparable: no .md, no leading ./, lowercased."""
    t = target.strip().replace("\\", "/")
    if t.startswith("./"):
        t = t[2:]
    return _strip_md(t).lower()


def _collapse(path: str, *, clamp: bool = True) -> str:
    """Collapse '.' and '..' segments textually, never touching the filesystem.

    With clamp=False, a path that climbs above the vault root collapses to ''.
    """
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            elif not clamp:
                return ""
            continue
        parts.append(part)
    return "/".join(parts)


def _md_url_candidates(url: str, linking_file_rel: str) -> list[str]:
    """The vault-relative paths a markdown-link URL could mean.

    Obsidian writes these either from the vault root or relative to the linking
    note, depending on a setting, and the text alone cannot tell them apart, so
    both readings come back and the caller matches whichever one moved. A `./` or
    `../` prefix settles it: only the relative reading comes back. Anything with a
    scheme, or a fragment-only target, is not a vault path at all.
    """
    if not url or url.startswith("#") or _SCHEME.match(url):
        return []
    path_part = url.split("#", 1)[0]
    if not path_part:
        return []
    decoded = unquote(path_part).replace("\\", "/")
    explicit = decoded.startswith(("./", "../"))
    decoded = decoded.lstrip("/")
    base = Path(linking_file_rel).parent.as_posix()
    if base in ("", "."):
        readings = [decoded]
    elif explicit:
        # The prefix says relative outright, so there is no root reading to try.
        readings = [f"{base}/{decoded}"]
    else:
        readings = [decoded, f"{base}/{decoded}"]

    candidates = []
    for reading in readings:
        collapsed = _collapse(reading)
        if not collapsed:
            continue
        if not collapsed.lower().endswith(".md"):
            collapsed += ".md"
        candidates.append(collapsed)
    return candidates


def _relative_to(target_rel: str, linking_file_rel: str) -> str:
    """Express a vault-relative target as a path relative to the linking note.

    Keeps a link written as `../target.md` looking like `../renamed.md` instead of
    being rewritten from the vault root, which would read as someone else's edit.
    """
    target_parts = target_rel.split("/")
    base_parts = Path(linking_file_rel).parent.as_posix().split("/")
    if base_parts == [""] or base_parts == ["."]:
        base_parts = []
    common = 0
    while (
        common < len(base_parts)
        and common < len(target_parts) - 1
        and base_parts[common] == target_parts[common]
    ):
        common += 1
    ups = [".."] * (len(base_parts) - common)
    return "/".join(ups + target_parts[common:])


def _after_move(rel: str, source: str, destination: str) -> str:
    """Where a vault path sits after the move: under the destination if it sat under the source."""
    if rel == source:
        return destination
    if rel.startswith(source + "/"):
        return f"{destination}/{rel[len(source) + 1:]}"
    return rel


def _relative_link_target(url: str, linking_file_rel: str, existed: Callable[[str], bool]) -> str | None:
    """The vault path a markdown link names from its note's folder, when that reading is clear.

    A `./` or `../` prefix says so outright. An unprefixed path can also be read from the
    vault root, so it counts only when the note's folder holds the file and the root does
    not. A note at the root has only the one reading, which still resolves from the root
    wherever the note goes, so it is left alone.
    Either way the file must have existed: like Obsidian, a link that resolved to
    nothing is left alone.
    """
    if not url or url.startswith("#") or _SCHEME.match(url):
        return None
    decoded = unquote(url.split("#", 1)[0]).replace("\\", "/")
    explicit = decoded.startswith(("./", "../"))
    base = Path(linking_file_rel).parent.as_posix()
    if not decoded or decoded.startswith("/") or (base == "." and not explicit):
        return None
    # A link that climbs above the vault root never named a vault file.
    target = _collapse(f"{base}/{decoded}", clamp=False)
    if not target or not existed(target):
        return None
    if not explicit and existed(_collapse(decoded, clamp=False)):
        return None
    return target


def _moved_pairs(source: str, destination: str, *, before_move: bool = False) -> list[tuple[str, str]]:
    """The (old_rel, new_rel) markdown files this move affects.

    A file move is one pair; a directory move is one pair per markdown file that
    landed under the destination, or, for a dry run before the move, that sits
    under the source.
    """
    moved_path = config.VAULT_PATH / (source if before_move else destination)
    if moved_path.is_dir():
        pairs = []
        for path in moved_path.rglob("*.md"):
            rel = path.relative_to(config.VAULT_PATH)
            if _is_excluded(rel.parts) or any(p.startswith(".") for p in rel.parts):
                continue
            inner = path.relative_to(moved_path).as_posix()
            pairs.append((f"{source.rstrip('/')}/{inner}", (Path(destination) / inner).as_posix()))
        return pairs
    if destination.lower().endswith(".md"):
        return [(source, destination)]
    return []


def _rewrite_content(
    content: str,
    linking_file_rel: str,
    pairs: list[tuple[str, str]],
    unique_basenames: dict[str, int],
    moved_to: str | None = None,
    relink: Callable[[str], str | None] | None = None,
) -> tuple[str, int, list[str]]:
    """Return (new_content, links_rewritten, ambiguous_targets_left_alone).

    linking_file_rel is where the note sat when its links were written. A note that was
    itself moved passes moved_to, its new place, and relink, which repoints a relative
    markdown link at a file that did not move.
    """
    rewrites = 0
    ambiguous: list[str] = []

    by_path = {_strip_md(old).lower(): new for old, new in pairs}
    by_basename: dict[str, str] = {}
    for old, new in pairs:
        old_stem = Path(old).stem.lower()
        new_stem = Path(new).stem
        if old_stem != new_stem.lower():
            by_basename[old_stem] = new

    def wikilink(match: re.Match) -> str:
        nonlocal rewrites
        target = match.group("target")
        if not target.strip():
            return match.group(0)
        normalized = _normalize_target(target)

        if "/" in normalized:
            # A path-qualified link keeps naming a path, so it follows the move.
            new_rel = by_path.get(normalized)
            if new_rel is None:
                return match.group(0)
            replacement = _strip_md(new_rel)
        else:
            # A bare basename resolves by name wherever the note sits, so a move
            # alone never touches it; only a rename does. A note at the vault root
            # would otherwise look like a path link and get a folder glued on.
            new_rel = by_basename.get(normalized)
            if new_rel is None:
                return match.group(0)
            if unique_basenames.get(normalized, 0) > 1:
                ambiguous.append(target.strip())
                return match.group(0)
            replacement = Path(new_rel).stem

        rewritten = f"{match.group('embed')}[[{replacement}{match.group('tail')}]]"
        if rewritten != match.group(0):
            rewrites += 1
        return rewritten

    def mdlink(match: re.Match) -> str:
        nonlocal rewrites
        url = match.group("url")
        new_rel = None
        was_relative = False
        for index, candidate in enumerate(_md_url_candidates(url, linking_file_rel)):
            new_rel = by_path.get(_strip_md(candidate).lower())
            if new_rel is not None:
                # Index 1 is the reading taken relative to the linking note. A
                # `./` or `../` prefix says so outright, even when the collapsed
                # path happens to coincide with the root-relative reading.
                decoded = unquote(url.split("#", 1)[0]).replace("\\", "/")
                was_relative = index == 1 or decoded.startswith(("./", "../"))
                break
        if new_rel is None and relink is not None:
            new_rel = relink(url)
            was_relative = True
        if new_rel is None:
            return match.group(0)
        target_path = _relative_to(new_rel, moved_to or linking_file_rel) if was_relative else new_rel
        if url.startswith("./") and not target_path.startswith("../"):
            target_path = f"./{target_path}"
        fragment = ""
        if "#" in url:
            fragment = "#" + url.split("#", 1)[1]
        encoded = quote(target_path) if "%" in url or " " in target_path else target_path
        rewritten = f"{match.group('embed')}[{match.group('text')}]({encoded}{fragment})"
        if rewritten != match.group(0):
            rewrites += 1
        return rewritten

    content = _WIKILINK.sub(wikilink, content)
    content = _MDLINK.sub(mdlink, content)
    return content, rewrites, ambiguous


def update_links_for_move(source: str, destination: str, *, dry_run: bool = False) -> dict:
    """Repoint every link in the vault that referred to the moved path.

    Returns a summary: the files changed, how many links were rewritten, any bare-basename
    links left alone because the basename is not unique, and any file whose write failed.
    Never raises: a failure to rewrite must not undo a move that already landed, so
    problems are logged and reported in the summary.

    dry_run runs before the move and writes nothing: the summary names the files that
    would change, and ``diffs`` holds a unified diff for each.
    """
    summary = {"files_updated": 0, "links_updated": 0, "files": [], "ambiguous": [], "failed": []}
    # Name both the way the walk names files: "a.md", never "./a.md" or "dir/".
    source, destination = Path(source).as_posix(), Path(destination).as_posix()
    if dry_run:
        summary["diffs"] = {}
    try:
        pairs = _moved_pairs(source, destination, before_move=dry_run)
        if not pairs:
            return summary
        unique_basenames = _basename_counts(pairs, before_move=dry_run)
        # The moved notes, by where the walk finds them: their old paths before a
        # dry run's move, their new paths after a real one.
        moved = {(old if dry_run else new): (old, new) for old, new in pairs}

        def existed(target: str) -> bool:
            """Whether a vault path named a file before the move, as written or with .md."""
            for candidate in (target, f"{target}.md"):
                if not dry_run:
                    now = _after_move(candidate, source, destination)
                    if now == candidate and _after_move(candidate, destination, source) != candidate:
                        continue  # under the destination, which was empty before the move
                    candidate = now
                if (config.VAULT_PATH / candidate).is_file():
                    return True
            return False

        for path, rel in _iter_markdown_files():
            old_rel, new_rel = moved.get(rel, (rel, rel))
            relink = None
            if old_rel != new_rel:
                # A moved note's own links: a self-link follows the rename like any
                # other, and a relative link is re-expressed from the new folder.
                def relink(url: str) -> str | None:
                    target = _relative_link_target(url, old_rel, existed)
                    return None if target is None else _after_move(target, source, destination)
            if path.is_symlink():
                # The read paths' rule: a symlink may point outside the vault, and
                # rewriting it would put that outside content into an ordinary vault file.
                continue
            try:
                # Refuses a hardlink, whose other name may sit outside the vault.
                resolve_vault_read_path(rel)
                if path.stat().st_size > config.MAX_CONTENT_SIZE:
                    continue
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError, ValueError):
                # Unreadable, not text, or refused by the read guard: skipped on
                # purpose, and counted nowhere, because a file we must not read is
                # a file we must not rewrite.
                continue

            new_content, rewrites, ambiguous = _rewrite_content(
                content, old_rel, pairs, unique_basenames, moved_to=new_rel, relink=relink
            )
            summary["ambiguous"].extend(ambiguous)
            if not rewrites:
                continue
            if dry_run:
                size = len(new_content.encode("utf-8"))
                if size > config.MAX_CONTENT_SIZE:
                    # write_file_atomic would refuse it; report what the real move would.
                    summary["failed"].append({
                        "path": new_rel,
                        "error": f"Content size {size} bytes exceeds limit of {config.MAX_CONTENT_SIZE} bytes",
                    })
                    continue
                summary["diffs"][new_rel] = _unified_diff(new_rel, content, new_content)
            else:
                try:
                    write_file_atomic(rel, new_content, create_dirs=False)
                except Exception as e:
                    # One bad file costs one file, not the rest of the pass.
                    logger.error(f"update_links_for_move: write failed for {rel}: {e}")
                    summary["failed"].append({"path": rel, "error": str(e)})
                    continue
            summary["files_updated"] += 1
            summary["links_updated"] += rewrites
            summary["files"].append(new_rel)
    except Exception as e:  # pragma: no cover - defensive, the move already landed
        logger.error(f"update_links_for_move error: {e}")
        summary["error"] = str(e)

    summary["ambiguous"] = sorted(set(summary["ambiguous"]))
    return summary
