"""Per-language evidence that tool responses are non-ASCII-safe and smaller.

This file is the reproducible evidence behind the encoding change: running
`pytest tests/test_serialization_encoding.py` confirms, for a broad set of
scripts, that

1. responses emit the text verbatim as UTF-8 (no \\uXXXX escapes),
2. the decoded JSON object is identical to what the old ensure_ascii=True
   encoder produced (behavior-preserving), and
3. the non-ASCII payload is strictly smaller than the escaped form (the saving),

across every tool that returns content: read, write, list, search, and the
vault_edit dry-run diff. The default ensure_ascii=True escaped each non-ASCII
character into a \\uXXXX sequence (12 chars for a single non-BMP emoji), which
inflated every response and, in day-to-day use of a Korean-language vault, made
echoed-back paths fail to match stored files (duplicate notes, missed search
hits). manage.py and write.py previously called json.dumps directly; the
parametrized tool tests below also prove they now route through the shared
encoder.
"""

import json
from datetime import date

import pytest

from obsidian_vault_mcp.serialization import dumps
from obsidian_vault_mcp.tools.manage import vault_delete, vault_list, vault_move
from obsidian_vault_mcp.tools.read import vault_read
from obsidian_vault_mcp.tools.search import vault_search, vault_search_frontmatter
from obsidian_vault_mcp.tools.write import vault_append, vault_edit, vault_write

# (id, sample text, a substring to search for, a filename stem) per script.
LANGUAGES = [
    ("korean", "회의에서 결정된 사항은 다음과 같습니다", "결정", "회의록"),
    ("japanese", "本日の会議で決定した事項は以下のとおりです", "会議", "議事録"),
    ("chinese", "今天会议决定的事项如下所示", "会议", "会议记录"),
    ("cyrillic", "Решения принятые на сегодняшней встрече", "Решения", "Протокол"),
    ("arabic", "القرارات المتخذة في اجتماع اليوم", "القرارات", "محضر"),
    ("devanagari", "आज की बैठक में लिए गए निर्णय", "बैठक", "कार्यवृत्त"),
    ("greek", "Οι αποφάσεις της σημερινής συνάντησης", "αποφάσεις", "Πρακτικά"),
    ("hebrew", "ההחלטות שהתקבלו בפגישה היום", "ההחלטות", "פרוטוקול"),
    ("thai", "การประชุมในวันนี้มีการตัดสินใจหลายอย่าง", "ประชุม", "บันทึก"),
    ("accented_latin", "Décisions prises lors de la réunion", "Décisions", "réunion"),
    ("emoji_non_bmp", "Done shipped 🚀 review notes 📝", "🚀", "notes_🚀"),
]
LANG_IDS = [row[0] for row in LANGUAGES]


# --- dumps() unit behavior -----------------------------------------------------

def test_compact_separators_have_no_whitespace():
    raw = dumps({"a": 1, "b": 2})
    assert ", " not in raw
    assert ": " not in raw
    assert raw == '{"a":1,"b":2}'


def test_iso_dates_still_serialized():
    """Regression guard for #5: the date encoder survives the encoding change."""
    parsed = json.loads(dumps({"created": date(2026, 4, 5), "title": "회의"}))
    assert parsed["created"] == "2026-04-05"
    assert parsed["title"] == "회의"


def test_ascii_content_decodes_identically_to_stdlib():
    """Pure-ASCII payloads are unchanged apart from separator whitespace."""
    obj = {"path": "notes/meeting.md", "n": 1, "ok": True}
    assert "\\u" not in dumps(obj)
    assert json.loads(dumps(obj)) == json.loads(json.dumps(obj)) == obj


# --- per-language dumps() evidence ---------------------------------------------

@pytest.mark.parametrize("lang,text,term,stem", LANGUAGES, ids=LANG_IDS)
def test_dumps_emits_verbatim_without_escapes(lang, text, term, stem):
    raw = dumps({"title": text})
    assert text in raw
    assert "\\u" not in raw


@pytest.mark.parametrize("lang,text,term,stem", LANGUAGES, ids=LANG_IDS)
def test_dumps_roundtrip_is_identity(lang, text, term, stem):
    obj = {"path": f"{stem}.md", "body": text, "nested": {"title": text}}
    assert json.loads(dumps(obj)) == obj


@pytest.mark.parametrize("lang,text,term,stem", LANGUAGES, ids=LANG_IDS)
def test_non_ascii_payload_is_smaller_and_identical(lang, text, term, stem):
    """The saving: non-ASCII UTF-8 output is strictly smaller than the escaped
    form, and both decode to the same object."""
    obj = {"path": f"{stem}.md", "match_context": text, "frontmatter": {"title": text}}
    escaped = json.dumps(obj, ensure_ascii=True)  # the old behavior
    actual = dumps(obj)  # ensure_ascii=False + compact
    assert json.loads(escaped) == json.loads(actual) == obj
    assert len(actual.encode("utf-8")) < len(escaped.encode("utf-8"))


# --- per-language end-to-end through the real tools ----------------------------

@pytest.mark.parametrize("lang,text,term,stem", LANGUAGES, ids=LANG_IDS)
def test_vault_write_response_unescaped(vault_dir, lang, text, term, stem):
    raw = vault_write(f"{stem}.md", f"{text}\n")
    assert stem in raw
    assert "\\u" not in raw


@pytest.mark.parametrize("lang,text,term,stem", LANGUAGES, ids=LANG_IDS)
def test_vault_read_roundtrip_unescaped(vault_dir, lang, text, term, stem):
    path = f"{stem}.md"
    vault_write(path, f'---\ntitle: "{text}"\n---\n\n{text}\n')
    raw = vault_read(path)
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert text in parsed["content"]
    assert parsed["frontmatter"]["title"] == text


@pytest.mark.parametrize("lang,text,term,stem", LANGUAGES, ids=LANG_IDS)
def test_vault_list_response_unescaped(vault_dir, lang, text, term, stem):
    vault_write(f"{stem}.md", f"{text}\n")
    raw = vault_list("")
    assert stem in raw
    assert "\\u" not in raw


@pytest.mark.parametrize("lang,text,term,stem", LANGUAGES, ids=LANG_IDS)
def test_vault_search_response_unescaped(vault_dir, lang, text, term, stem):
    vault_write(f"{stem}.md", f'---\ntitle: "{text}"\n---\n\n{text}\n')
    raw = vault_search(term)
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert parsed["total_matches"] >= 1
    assert any(term in result["match_context"] for result in parsed["results"])


@pytest.mark.parametrize("lang,text,term,stem", LANGUAGES, ids=LANG_IDS)
def test_vault_edit_dryrun_diff_unescaped(vault_dir, lang, text, term, stem):
    path = f"{stem}.md"
    vault_write(path, f"{text}\n")  # body without frontmatter so old_text is unique
    raw = vault_edit(path, [{"old_text": text, "new_text": f"{text} EDITED"}], dry_run=True)
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert text in parsed["diff"]


# --- kwargs override contract (the new defaults must be overridable) -----------

def test_dumps_respects_explicit_ensure_ascii_override():
    raw = dumps({"title": "회의"}, ensure_ascii=True)
    assert "회의" not in raw
    assert "\\ud68c" in raw


def test_dumps_respects_explicit_separators_override():
    assert dumps({"a": 1, "b": 2}, separators=(", ", ": ")) == '{"a": 1, "b": 2}'


# --- robustness: non-UTF-8 (surrogate-escaped) filesystem names ----------------

def test_dumps_output_is_always_utf8_encodable():
    # Files whose names are not valid UTF-8 reach us as lone surrogates via
    # os.fsdecode(surrogateescape). The response string must still encode for the
    # wire; otherwise a single odd filename crashes the response at transport.
    obj = {"path": "bad\udce9name.md", "items": []}
    raw = dumps(obj)
    raw.encode("utf-8")  # must not raise
    # and the escaped fallback must still round-trip (not drop/replace the surrogate)
    assert json.loads(raw) == obj


# --- non-ASCII error-path responses (except branches route through dumps too) --

def test_vault_read_missing_non_ascii_path_unescaped(vault_dir):
    raw = vault_read("없는폴더/회의록.md")
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert "error" in parsed
    assert parsed["path"] == "없는폴더/회의록.md"


def test_vault_edit_nonmatching_old_text_error_unescaped(vault_dir):
    vault_write("회의.md", "원본 내용\n")
    raw = vault_edit("회의.md", [{"old_text": "존재하지않는텍스트", "new_text": "x"}])
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert "error" in parsed
    assert parsed["path"] == "회의.md"


# --- vault_move / vault_delete echo non-ASCII paths verbatim -------------------

def test_vault_move_response_unescaped(vault_dir):
    vault_write("원본/회의.md", "내용\n")
    raw = vault_move("원본/회의.md", "보관/회의_이동.md")
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert parsed["source"] == "원본/회의.md"
    assert parsed["destination"] == "보관/회의_이동.md"


def test_vault_delete_response_unescaped(vault_dir):
    vault_write("삭제대상.md", "내용\n")
    raw = vault_delete("삭제대상.md", confirm=True)
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert parsed["path"] == "삭제대상.md"


def test_vault_append_response_unescaped(vault_dir):
    raw = vault_append("추가/노트.md", "추가된 내용\n")
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert parsed["path"] == "추가/노트.md"
    assert parsed["created"] is True


# --- vault_search_frontmatter returns non-ASCII frontmatter verbatim -----------

def test_vault_search_frontmatter_unescaped(vault_dir, monkeypatch):
    from obsidian_vault_mcp import server
    from obsidian_vault_mcp.frontmatter_index import FrontmatterIndex

    idx = FrontmatterIndex()
    idx._index = {"회의록.md": {"title": "주간 회의 議事録", "tags": ["업무", "회의"]}}
    monkeypatch.setattr(server, "frontmatter_index", idx)

    raw = vault_search_frontmatter("title", "주간 회의 議事録", match_type="exact")
    assert "\\u" not in raw
    parsed = json.loads(raw)
    assert parsed["total"] >= 1
    assert parsed["results"][0]["frontmatter"]["title"] == "주간 회의 議事録"
