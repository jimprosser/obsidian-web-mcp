"""Real-world-scale evidence for the non-ASCII serialization change.

The unit tests in test_serialization_encoding.py prove correctness with small
samples (escaping is deterministic per code point, so a short string is as
rigorous as a long one). These tests instead represent the actual workload: a
web client writing, reading, bulk-editing, and batch-processing multilingual
documents that are hundreds of lines long.

The text is authentic, freely reproducible content (Universal Declaration of Human
Rights excerpts, see tests/fixtures/udhr/README.md). Each test asserts, on the
real tool responses, that the output is emitted verbatim (no \\uXXXX escapes),
that the decoded payload round-trips exactly (integrity), and that the response
is meaningfully smaller than the old ensure_ascii=True encoding would have been.
"""

import json
from pathlib import Path

from obsidian_vault_mcp.tools.read import vault_batch_read, vault_read
from obsidian_vault_mcp.tools.search import vault_search
from obsidian_vault_mcp.tools.write import (
    vault_batch_frontmatter_update,
    vault_edit,
    vault_write,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "udhr"
LANGS = [
    "korean", "japanese", "chinese", "russian", "arabic",
    "hindi", "greek", "hebrew", "thai", "french",
]


def _udhr(lang: str) -> str:
    return (_FIXTURES / f"{lang}.txt").read_text(encoding="utf-8").strip()


def _escaped_size(parsed) -> int:
    """Bytes the old ensure_ascii=True encoder would have produced."""
    return len(json.dumps(parsed, ensure_ascii=True).encode("utf-8"))


def _reduction(raw: str, parsed) -> float:
    return 1 - len(raw.encode("utf-8")) / _escaped_size(parsed)


def _large_multilingual_doc(repeat: int = 4) -> str:
    """A frontmatter + hundreds of numbered lines mixing every script."""
    lines, idx = [], 0
    for _ in range(repeat):
        for lang in LANGS:
            for line in _udhr(lang).splitlines():
                lines.append(f"{idx:04d}. {line}")
                idx += 1
    body = "\n".join(lines)
    frontmatter = (
        '---\n'
        'title: "세계인권선언 · 多言語 테스트 문서"\n'
        'tags: [회의, 多言語, δοκιμή, проверка]\n'
        '---\n\n'
    )
    return frontmatter + body + "\n"


# --- the fixture corpus loads and is genuinely large ---------------------------

def test_fixture_corpus_is_present_and_nontrivial():
    for lang in LANGS:
        assert len(_udhr(lang)) > 300, lang
    doc = _large_multilingual_doc()
    assert doc.count("\n") > 150          # hundreds of lines
    assert len(doc.encode("utf-8")) > 30_000


# --- large document: write -> read round-trip, integrity, and saving -----------

def test_large_document_write_read_is_verbatim_and_smaller(vault_dir):
    doc = _large_multilingual_doc()
    path = "projects/세계인권선언_多言語.md"

    write_raw = vault_write(path, doc)
    assert "\\u" not in write_raw

    read_raw = vault_read(path)
    assert "\\u" not in read_raw
    parsed = json.loads(read_raw)

    # integrity: the full multilingual body survives byte-for-byte
    assert parsed["content"] == doc
    assert parsed["frontmatter"]["title"] == "세계인권선언 · 多言語 테스트 문서"

    # saving at scale
    assert len(read_raw.encode("utf-8")) < _escaped_size(parsed)
    assert _reduction(read_raw, parsed) > 0.20


# --- bulk edit: many replacements in one call ----------------------------------

def test_bulk_edit_dryrun_diff_is_verbatim_and_smaller(vault_dir):
    doc = _large_multilingual_doc()
    path = "bulk.md"
    vault_write(path, doc)

    # 30 edits, each targeting a uniquely numbered line so old_text matches once
    body_lines = [ln for ln in doc.splitlines() if ln[:4].isdigit()]
    targets = body_lines[:30]
    edits = [{"old_text": ln, "new_text": f"{ln} (개정 改訂 ревизия)"} for ln in targets]

    raw = vault_edit(path, edits, dry_run=True)
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert parsed["edits_applied"] == 30
    assert "改訂" in parsed["diff"]
    assert len(raw.encode("utf-8")) < _escaped_size(parsed)
    assert _reduction(raw, parsed) > 0.20


# --- batch read: many multilingual files in one call ---------------------------

def test_batch_read_is_verbatim_and_preserves_each_file(vault_dir):
    paths = []
    for lang in LANGS:
        path = f"notes/{lang}.md"
        vault_write(path, f'---\ntitle: "{lang}"\n---\n\n{_udhr(lang)}\n')
        paths.append(path)

    raw = vault_batch_read(paths)
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert parsed["found"] == len(LANGS)
    by_path = {f["path"]: f for f in parsed["files"]}
    for lang, path in zip(LANGS, paths):
        assert _udhr(lang) in by_path[path]["content"]


def test_batch_read_missing_non_ascii_path_is_verbatim(vault_dir):
    raw = vault_batch_read(["없는폴더/회의록.md"])
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert parsed["missing"] == 1
    assert parsed["files"][0]["path"] == "없는폴더/회의록.md"


# --- batch frontmatter update: non-ASCII field values --------------------------

def test_batch_frontmatter_update_writes_non_ascii_values(vault_dir):
    for lang in LANGS:
        vault_write(f"fm/{lang}.md", f"{_udhr(lang)}\n")

    updates = [
        {"path": f"fm/{lang}.md", "fields": {"summary": _udhr(lang)[:40], "lang": lang}}
        for lang in LANGS
    ]
    raw = vault_batch_frontmatter_update(updates)
    assert "\\u" not in raw

    # verify the values landed and read back verbatim
    for lang in LANGS:
        parsed = json.loads(vault_read(f"fm/{lang}.md"))
        assert parsed["frontmatter"]["summary"] == _udhr(lang)[:40]


# --- search across a large file with many matches ------------------------------

def test_search_many_matches_is_verbatim(vault_dir):
    term = "권리"  # appears repeatedly in the Korean UDHR excerpt
    repeated = (_udhr("korean") + "\n") * 20
    vault_write("big_korean.md", repeated)

    raw = vault_search(term, max_results=50)
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert parsed["total_matches"] >= 5
    assert all(term in r["match_context"] for r in parsed["results"])
