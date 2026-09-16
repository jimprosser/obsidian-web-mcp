"""Vault analytics tools for hygiene and structural diagnostics.

Read-only, pure-filesystem diagnostics over the markdown in a vault: missing or
incomplete frontmatter, broken ``[[wikilinks]]``, near-duplicate tag variants,
and files that are not valid UTF-8. No plugin, no network, no subprocess, no new
config. Every walk is rooted at ``resolve_vault_path`` (or the vault root) so the
same traversal/dotfile guard every other tool uses applies here too, and the
standard ``EXCLUDED_DIRS`` (``.obsidian``, ``.trash``, ...) are skipped.
"""

import logging
import posixpath
import re
from collections import Counter, defaultdict
from pathlib import Path

import frontmatter

from .. import config
from ..serialization import dumps
from ..vault import resolve_vault_path

logger = logging.getLogger(__name__)

WIKILINK_RE = re.compile(r"\[\[([^\]]+)\]\]")

# Per-file read cap for analysis, aligned with the 1 MB write cap. A file over this is read
# only up to the cap (so top-of-file frontmatter still parses) and separately surfaced as an
# "oversized_files" finding -- one giant note can't spike memory on a tunnel-reachable server.
_MAX_ANALYZE_BYTES = config.MAX_CONTENT_SIZE


def _vault_root() -> Path:
    return config.VAULT_PATH.resolve()


def _iter_vault_files(path_prefix: str = "", pattern: str = "*") -> list[Path]:
    """Walk the vault (or a sub-prefix) yielding non-excluded, real files.

    ``resolve_vault_path`` enforces the traversal/dotfile/null-byte guard; an
    empty prefix walks the whole vault from its root.
    """
    root = resolve_vault_path(path_prefix) if path_prefix else _vault_root()
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {path_prefix}")

    files: list[Path] = []
    for path in root.rglob(pattern):
        if any(part in config.EXCLUDED_DIRS for part in path.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        files.append(path)
    return files


def _relative_to_vault_root(path: Path) -> str:
    return str(path.relative_to(_vault_root())).replace("\\", "/")


def _scan_encoding_issues(path_prefix: str = "", max_results: int = 100) -> list[dict]:
    """Return markdown files under the prefix that are not valid UTF-8."""
    issues: list[dict] = []
    for path in _iter_vault_files(path_prefix, "*.md"):
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError as e:
            issues.append(
                {
                    "path": _relative_to_vault_root(path),
                    "position": e.start,
                    "reason": e.reason,
                }
            )
            if len(issues) >= max_results:
                break
    return issues


def _load_posts(path_prefix: str = "") -> tuple[list[dict], dict[str, list[str]], dict[str, str]]:
    vault_root = _vault_root()
    files = _iter_vault_files(path_prefix, "*.md")
    vault_files = _iter_vault_files(path_prefix, "*")
    posts: list[dict] = []
    basename_index: dict[str, list[str]] = defaultdict(list)
    path_index: dict[str, str] = {}

    for path in vault_files:
        rel = str(path.relative_to(vault_root)).replace("\\", "/")
        basename_index[path.stem.lower()].append(rel)
        path_index[rel.lower()] = rel
        path_index[path.with_suffix("").relative_to(vault_root).as_posix().lower()] = rel

    for path in files:
        rel = str(path.relative_to(vault_root)).replace("\\", "/")
        # Cap the per-file read so one pathological note can't spike memory; an oversized
        # file is read only up to the cap (top-of-file frontmatter still parses).
        try:
            oversized = path.stat().st_size > _MAX_ANALYZE_BYTES
        except OSError:
            oversized = False
        try:
            if oversized:
                with path.open("r", encoding="utf-8", errors="ignore") as handle:
                    raw = handle.read(_MAX_ANALYZE_BYTES)
            else:
                raw = path.read_text(encoding="utf-8")
            post = frontmatter.loads(raw)
            metadata = dict(post.metadata)
            body = post.content
        except UnicodeDecodeError:
            metadata = {}
            body = ""
        except Exception:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                body = handle.read(_MAX_ANALYZE_BYTES)
            metadata = {}
        posts.append(
            {
                "path": rel,
                "body": body,
                "frontmatter": metadata,
            }
        )

    return posts, basename_index, path_index


def _oversized_files(path_prefix: str = "", max_results: int = 100) -> list[dict]:
    """Markdown files larger than the analysis cap.

    Surfaced as a finding so a file that ``_load_posts`` only read up to the cap is visible
    rather than silently under-analysed.
    """
    vault_root = _vault_root()
    findings: list[dict] = []
    for path in _iter_vault_files(path_prefix, "*.md"):
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > _MAX_ANALYZE_BYTES:
            rel = str(path.relative_to(vault_root)).replace("\\", "/")
            findings.append({"path": rel, "size_bytes": size, "limit_bytes": _MAX_ANALYZE_BYTES})
            if len(findings) >= max_results:
                break
    return findings


def _extract_tags(frontmatter_data: dict) -> list[str]:
    tags = frontmatter_data.get("tags", [])
    if isinstance(tags, str):
        return [tags]
    if isinstance(tags, list):
        return [str(tag) for tag in tags]
    return []


def _split_wikilink_target(target: str) -> str:
    clean = target.split("|", 1)[0].split("#", 1)[0].strip()
    return clean.replace("\\", "/")


def _normalize_relative_candidate(source_path: str, candidate: str) -> str | None:
    if not candidate:
        return ""

    if candidate.startswith("/"):
        normalized = posixpath.normpath(candidate.lstrip("/"))
    elif candidate.startswith("./") or candidate.startswith("../"):
        source_parent = posixpath.dirname(source_path)
        normalized = posixpath.normpath(posixpath.join(source_parent, candidate))
    else:
        normalized = posixpath.normpath(candidate)

    if normalized in ("", ".") or normalized.startswith("../"):
        return None
    return normalized


def _candidate_lookup_key(relative_candidate: str) -> str:
    if Path(relative_candidate).suffix:
        return relative_candidate.lower()
    return f"{relative_candidate}.md".lower()


def _classify_wikilink_target(
    source_path: str,
    target: str,
    basename_index: dict[str, list[str]],
    path_index: dict[str, str],
) -> dict:
    clean = _split_wikilink_target(target)
    if not clean:
        return {"status": "ok_exact", "target": target}

    relative_candidate = _normalize_relative_candidate(source_path, clean)
    if relative_candidate is not None:
        exact_match = path_index.get(_candidate_lookup_key(relative_candidate))
        if exact_match:
            return {
                "status": "ok_exact",
                "target": target,
                "resolved_candidate": exact_match,
            }

    basename_matches = basename_index.get(Path(clean).stem.lower(), [])
    if "/" not in clean and "." not in Path(clean).name:
        if len(basename_matches) == 1:
            result = {
                "status": "ok_basename",
                "target": target,
                "match_count": 1,
                "resolved_candidate": basename_matches[0],
            }
            return result
        if len(basename_matches) > 1:
            return {
                "status": "ambiguous_basename",
                "target": target,
                "match_count": len(basename_matches),
                "candidates": basename_matches[:5],
            }
        return {"status": "missing_target", "target": target}

    if len(basename_matches) == 1:
        result = {
            "status": "repairable_path_mismatch",
            "target": target,
            "match_count": 1,
            "resolved_candidate": basename_matches[0],
        }
        if relative_candidate is not None:
            result["requested_candidate"] = relative_candidate
        return result
    if len(basename_matches) > 1:
        result = {
            "status": "ambiguous_path_mismatch",
            "target": target,
            "match_count": len(basename_matches),
            "candidates": basename_matches[:5],
        }
        if relative_candidate is not None:
            result["requested_candidate"] = relative_candidate
        return result

    result = {"status": "missing_target", "target": target}
    if relative_candidate is not None:
        result["requested_candidate"] = relative_candidate
    return result


def _iter_wikilink_matches(text: str) -> list[dict]:
    matches: list[dict] = []
    for match in WIKILINK_RE.finditer(text):
        start = match.start()
        line = text.count("\n", 0, start) + 1
        line_start = text.rfind("\n", 0, start)
        column = start + 1 if line_start == -1 else start - line_start
        matches.append(
            {
                "target": match.group(1),
                "line": line,
                "column": column,
            }
        )
    return matches


def _frontmatter_missing(posts: list[dict]) -> list[dict]:
    return [{"path": post["path"]} for post in posts if not post["frontmatter"]]


def _required_frontmatter_missing(posts: list[dict], required_fields: list[str]) -> list[dict]:
    if not required_fields:
        return []
    findings = []
    for post in posts:
        missing = [field for field in required_fields if field not in post["frontmatter"]]
        if missing:
            findings.append({"path": post["path"], "missing_fields": missing})
    return findings


def _broken_wikilinks(
    posts: list[dict],
    basename_index: dict[str, list[str]],
    path_index: dict[str, str],
) -> list[dict]:
    findings = []
    for post in posts:
        for match in _iter_wikilink_matches(post["body"]):
            classification = _classify_wikilink_target(post["path"], match["target"], basename_index, path_index)
            if not classification["status"].startswith("ok_"):
                findings.append(
                    {
                        "path": post["path"],
                        "line": match["line"],
                        "column": match["column"],
                        **classification,
                    }
                )
    return findings


def _broken_wikilink_breakdown(findings: list[dict]) -> dict[str, int]:
    counts = Counter(item["status"] for item in findings)
    return {
        "total": len(findings),
        "repairable": counts.get("repairable_path_mismatch", 0),
        "missing_target": counts.get("missing_target", 0),
        "ambiguous": counts.get("ambiguous_basename", 0) + counts.get("ambiguous_path_mismatch", 0),
    }


def _suspicious_tag_variants(posts: list[dict]) -> list[dict]:
    raw_by_normalized: dict[str, set[str]] = defaultdict(set)
    usage_count: Counter[str] = Counter()
    for post in posts:
        for tag in _extract_tags(post["frontmatter"]):
            normalized = tag.strip().lower()
            if not normalized:
                continue
            raw_by_normalized[normalized].add(tag)
            usage_count[normalized] += 1

    findings = []
    for normalized, variants in raw_by_normalized.items():
        if len(variants) > 1:
            findings.append(
                {
                    "normalized_tag": normalized,
                    "variants": sorted(variants),
                    "usage_count": usage_count[normalized],
                }
            )
    return sorted(findings, key=lambda item: (-item["usage_count"], item["normalized_tag"]))


def vault_analytics_summary(
    path_prefix: str = "",
    required_frontmatter: list[str] | None = None,
    max_examples: int = 3,
) -> str:
    """Return a compact analytics summary for vault hygiene."""
    try:
        posts, basename_index, path_index = _load_posts(path_prefix)
        encoding_issues = _scan_encoding_issues(path_prefix, max_results=1000)
        oversized = _oversized_files(path_prefix, max_results=1000)
        frontmatter_missing = _frontmatter_missing(posts)
        required_missing = _required_frontmatter_missing(posts, required_frontmatter or [])
        broken_wikilinks = _broken_wikilinks(posts, basename_index, path_index)
        broken_wikilink_breakdown = _broken_wikilink_breakdown(broken_wikilinks)
        suspicious_tags = _suspicious_tag_variants(posts)

        summary = {
            "path_prefix": path_prefix,
            "file_count": len(posts),
            "findings": {
                "frontmatter_missing": len(frontmatter_missing),
                "required_frontmatter_missing": len(required_missing),
                "broken_wikilinks": broken_wikilink_breakdown["total"],
                "broken_wikilinks_repairable": broken_wikilink_breakdown["repairable"],
                "broken_wikilinks_missing_target": broken_wikilink_breakdown["missing_target"],
                "broken_wikilinks_ambiguous": broken_wikilink_breakdown["ambiguous"],
                "suspicious_tag_variants": len(suspicious_tags),
                "encoding_issues": len(encoding_issues),
                "oversized_files": len(oversized),
            },
            "examples": {
                "frontmatter_missing": frontmatter_missing[:max_examples],
                "required_frontmatter_missing": required_missing[:max_examples],
                "broken_wikilinks": broken_wikilinks[:max_examples],
                "suspicious_tag_variants": suspicious_tags[:max_examples],
                "encoding_issues": encoding_issues[:max_examples],
                "oversized_files": oversized[:max_examples],
            },
        }
        return dumps(summary)
    except ValueError as e:
        return dumps({"error": str(e), "path_prefix": path_prefix})
    except Exception as e:
        logger.error(f"vault_analytics_summary error for {path_prefix!r}: {e}")
        return dumps({"error": str(e), "path_prefix": path_prefix})


def vault_analytics_findings(
    category: str,
    path_prefix: str = "",
    required_frontmatter: list[str] | None = None,
    max_results: int = 50,
) -> str:
    """Return detailed findings for one analytics category."""
    try:
        posts, basename_index, path_index = _load_posts(path_prefix)
        required_frontmatter = required_frontmatter or []
        category_map = {
            "frontmatter_missing": lambda: _frontmatter_missing(posts),
            "required_frontmatter_missing": lambda: _required_frontmatter_missing(posts, required_frontmatter),
            "broken_wikilinks": lambda: _broken_wikilinks(posts, basename_index, path_index),
            "suspicious_tag_variants": lambda: _suspicious_tag_variants(posts),
            "encoding_issues": lambda: _scan_encoding_issues(path_prefix, max_results=max_results),
            "oversized_files": lambda: _oversized_files(path_prefix, max_results=max_results),
        }
        if category not in category_map:
            return dumps(
                {
                    "error": (
                        "Unsupported category. Use one of: frontmatter_missing, "
                        "required_frontmatter_missing, broken_wikilinks, "
                        "suspicious_tag_variants, encoding_issues, oversized_files"
                    ),
                    "category": category,
                }
            )

        findings = category_map[category]()
        return dumps(
            {
                "category": category,
                "path_prefix": path_prefix,
                "required_frontmatter": required_frontmatter,
                "count": len(findings),
                "results": findings[:max_results],
                "truncated": len(findings) > max_results,
            }
        )
    except ValueError as e:
        return dumps({"error": str(e), "category": category, "path_prefix": path_prefix})
    except Exception as e:
        logger.error(f"vault_analytics_findings error for {category!r}/{path_prefix!r}: {e}")
        return dumps({"error": str(e), "category": category, "path_prefix": path_prefix})
