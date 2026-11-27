"""vault_read's heading and outline: read one section of a note, or its headings.

A big note read whole costs its full size each time one part of it is needed. `heading`
returns only the section it names, its subheadings included; `outline` returns the
note's headings, each with its line and its section's size, so a caller can pick one.

The section rule is the one from the #109 review: ATX headings after up to three spaces;
fenced code and the leading frontmatter hold no headings; a setext heading ends a
section but is not one to read; lines split on '\\n' only. Every case goes through the
registered tool, like test_vault_edit_include_diff.py, so the input model, the audit
wrapper and the read path are all in the picture.
"""

import asyncio
import json
import time

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from obsidian_vault_mcp import config, content_extractors, context, server
from obsidian_vault_mcp.content_extractors import register_content_extractor


def call_tool(name: str, arguments: dict) -> dict:
    result = asyncio.run(server.mcp.call_tool(name, arguments))
    if isinstance(result, tuple):
        result = result[0]
    return json.loads("".join(getattr(block, "text", "") for block in result))


def read(path: str, **arguments) -> dict:
    return call_tool("vault_read", {"path": path, **arguments})


def raw_read(path: str, **arguments) -> str:
    result = asyncio.run(server.mcp.call_tool("vault_read", {"path": path, **arguments}))
    if isinstance(result, tuple):
        result = result[0]
    return "".join(getattr(block, "text", "") for block in result)


@pytest.fixture
def write_note(vault_dir):
    def write(text: str, name: str = "note.md") -> str:
        (vault_dir / name).write_text(text, encoding="utf-8")
        return name

    return write


def section(write_note, text: str, heading: str) -> str:
    """The content of the one section `heading` names in a note holding `text`."""
    result = read(write_note(text), heading=heading)
    assert "error" not in result, result
    assert "start_line" in result, result  # a section, not the whole note
    return result["content"]


def outline_headings(write_note, text: str) -> list[str]:
    return [entry["heading"] for entry in read(write_note(text), outline=True)["outline"]]


GUIDE = """---
status: active
---
# Guide

Intro.

## Setup

Install it.

### Linux

apt install it

## Usage

Run it.
"""


# --- The replies ---


def test_a_section_comes_back_with_its_lines_and_the_note_metadata(write_note):
    result = read(write_note(GUIDE), heading="## Usage")

    assert list(result) == ["path", "heading", "start_line", "end_line", "content", "metadata"]
    assert result["path"] == "note.md"
    assert result["heading"] == "# Guide > ## Usage"
    assert (result["start_line"], result["end_line"]) == (16, 18)
    assert result["content"] == "## Usage\n\nRun it.\n"
    assert set(result["metadata"]) >= {"size", "modified", "created"}


def test_a_section_takes_its_subheadings(write_note):
    result = read(write_note(GUIDE), heading="## Setup")

    assert result["content"] == "## Setup\n\nInstall it.\n\n### Linux\n\napt install it\n\n"
    assert (result["start_line"], result["end_line"]) == (8, 15)


def test_the_section_is_the_exact_slice_of_the_whole_read(write_note):
    name = write_note(GUIDE)
    whole = read(name)["content"]
    lines = whole.split("\n")

    for heading in ("# Guide", "## Setup", "### Linux", "## Usage"):
        result = read(name, heading=heading)
        assert result["content"] in whole
        assert result["content"] == "\n".join(lines[result["start_line"] - 1:result["end_line"]]) + "\n"


def test_the_outline_lists_each_heading_with_its_line_and_size(write_note):
    result = read(write_note(GUIDE), outline=True)

    assert list(result) == ["path", "size", "outline", "frontmatter", "metadata"]
    assert result["size"] == {"chars": len(GUIDE), "lines": 18}
    assert result["outline"] == [
        {"line": 4, "heading": "# Guide", "chars": len(GUIDE) - len("---\nstatus: active\n---\n")},
        {"line": 8, "heading": "## Setup", "chars": len("## Setup\n\nInstall it.\n\n### Linux\n\napt install it\n\n")},
        {"line": 12, "heading": "### Linux", "chars": len("### Linux\n\napt install it\n\n")},
        {"line": 16, "heading": "## Usage", "chars": len("## Usage\n\nRun it.\n")},
    ]
    assert result["frontmatter"] == {"status": "active"}


def test_a_plain_read_is_unchanged(write_note):
    result = read(write_note(GUIDE))

    assert list(result) == ["path", "content", "metadata", "frontmatter"]
    assert result["content"] == GUIDE


def test_the_size_counts_a_last_line_without_a_newline(write_note):
    assert read(write_note("# A\ntext"), outline=True)["size"] == {"chars": 8, "lines": 2}
    assert read(write_note("# A\ntext\n"), outline=True)["size"] == {"chars": 9, "lines": 2}


# --- The section rule ---


FENCED = """## Setup

Install:

```bash
# install deps
pip install foo
```

## Usage
"""


def test_a_hash_comment_in_a_fence_does_not_end_the_section(write_note):
    assert section(write_note, FENCED, "## Setup") == FENCED[:FENCED.index("## Usage")]
    assert outline_headings(write_note, FENCED) == ["## Setup", "## Usage"]


def test_a_heading_only_inside_a_fence_is_not_found(write_note):
    note = "# Top\n\n```\n## Example\n```\n"
    result = read(write_note(note), heading="## Example")

    assert result["error"].startswith("No heading matches")
    assert result["outline"] == [{"line": 1, "heading": "# Top", "chars": len(note)}]


@pytest.mark.parametrize(
    "fenced",
    [
        pytest.param("~~~\n# not\n~~~\n", id="tildes"),
        pytest.param("````\n```\n# not\n```\n````\n", id="a-longer-fence-holding-a-shorter-one"),
        pytest.param("```\n```python\n# not\n```\n", id="a-closer-with-an-info-string-does-not-close"),
        pytest.param("```\n~~~\n# not\n```\n", id="the-other-character-does-not-close"),
        pytest.param("   ```\n# not\n   ```\n", id="indented-three-spaces"),
        pytest.param("```js\n# not\n```   \n", id="trailing-spaces-after-the-closer"),
    ],
)
def test_fences_hold_no_headings(write_note, fenced):
    assert outline_headings(write_note, f"# A\n{fenced}# B\n") == ["# A", "# B"]


def test_an_unclosed_fence_runs_to_the_end_of_the_note(write_note):
    assert outline_headings(write_note, "# A\n```\n# not\n\n## still not\n") == ["# A"]


def test_four_spaces_before_backticks_is_not_a_fence(write_note):
    assert outline_headings(write_note, "# A\n\n    ```\n# B\n") == ["# A", "# B"]


def test_backticks_with_a_backtick_in_the_info_string_are_not_a_fence(write_note):
    assert outline_headings(write_note, "# A\n``` a`b\n# B\n") == ["# A", "# B"]


def test_the_frontmatter_holds_no_headings(write_note):
    note = "---\n# a YAML comment\ntags: [x]\n---\n# Real\n"

    assert outline_headings(write_note, note) == ["# Real"]
    assert read(write_note(note), outline=True)["outline"][0]["line"] == 5


def test_an_opening_rule_with_no_closing_line_is_not_frontmatter(write_note):
    assert outline_headings(write_note, "---\n# A\ntext\n") == ["# A"]


def test_frontmatter_after_a_bom_is_still_frontmatter(write_note):
    assert outline_headings(write_note, "﻿---\n# comment\n---\n# Real\n") == ["# Real"]


def test_a_heading_on_the_first_line_after_a_bom_is_a_heading(write_note):
    assert outline_headings(write_note, "﻿# Title\ntext\n") == ["# Title"]


@pytest.mark.parametrize("underline", ["========", "--------", "=", "---   "])
def test_a_setext_heading_ends_a_section(write_note, underline):
    note = f"## A\n\nalpha\n\nPart Two\n{underline}\n\nbeta\n"

    assert section(write_note, note, "## A") == "## A\n\nalpha\n\n"


def test_a_setext_heading_is_not_in_the_outline_and_not_a_target(write_note):
    name = write_note("# A\n\nPart Two\n========\n\nbeta\n")

    assert [e["heading"] for e in read(name, outline=True)["outline"]] == ["# A"]
    assert read(name, heading="Part Two")["error"].startswith("No heading matches")


def test_a_setext_heading_ends_the_section_at_its_paragraphs_first_line(write_note):
    note = "## A\n\nalpha\n\nPart\nTwo\n---\n"

    assert section(write_note, note, "## A") == "## A\n\nalpha\n\n"


def test_a_level_two_setext_heading_leaves_a_level_one_section_open(write_note):
    note = "# A\n\nPart Two\n--------\n\nbeta\n"

    assert section(write_note, note, "# A") == note


@pytest.mark.parametrize(
    "block",
    [
        pytest.param("- item\n---\n", id="a-list-item"),
        pytest.param("1. item\n---\n", id="an-ordered-list-item"),
        pytest.param("> quoted\n---\n", id="a-block-quote"),
        pytest.param("| a | b |\n| --- | --- |\n| 1 | 2 |\n---\n", id="a-table"),
        pytest.param("\n---\n", id="a-blank-line"),
        pytest.param("***\n", id="stars"),
    ],
)
def test_a_thematic_break_does_not_end_a_section(write_note, block):
    note = f"## A\n\n{block}after\n"

    assert section(write_note, note, "## A") == note


def test_a_delimiter_row_with_another_count_of_cells_is_no_table(write_note):
    # Not a table, so its lines are a paragraph, and the setext line under them ends the section.
    note = "# A\nalpha\n\na | b\n|-|-|-|\nText\n===\nafter\n"

    assert section(write_note, note, "# A") == "# A\nalpha\n\n"


@pytest.mark.parametrize(
    "header",
    [
        pytest.param("| A \\| B | C |", id="an-escaped-pipe"),
        pytest.param("| [[note\\|alias]] | C |", id="a-wiki-link-alias"),
    ],
)
def test_an_escaped_pipe_in_a_header_is_part_of_its_cell(write_note, header):
    # Two cells, as the delimiter has, so it is a table and the '---' under it is a break, not a heading.
    note = f"## A\nalpha\n\n{header}\n| --- | --- |\n| 1 | 2 |\n---\nafter\n"

    assert section(write_note, note, "## A") == note


@pytest.mark.parametrize(
    "item",
    [
        pytest.param("- ```bash\n  # install deps\n  ```\n", id="a-bullet"),
        pytest.param("10. ~~~\n    # install deps\n    ~~~\n", id="an-ordered-item-closed-four-spaces-in"),
        pytest.param("  - ```\n    # nested\n    ```\n", id="a-nested-item"),
    ],
)
def test_a_fence_opened_on_a_list_items_line_holds_no_headings(write_note, item):
    assert outline_headings(write_note, f"# A\n{item}## B\n") == ["# A", "## B"]


def test_a_fence_in_a_list_item_closes_only_within_the_items_indent(write_note):
    # Indented past the item's content, a fence line is code, so the fence stays open.
    assert outline_headings(write_note, "# A\n- ```\n         ```\n## not a heading\n") == ["# A"]


@pytest.mark.parametrize("line", ["   ## B", "##\tB", "## B   ", "## B ##", "## B #####"])
def test_heading_forms_that_count(write_note, line):
    note = f"# A\n{line}\ntext\n"

    assert outline_headings(write_note, note) == ["# A", line.strip()]
    assert section(write_note, note, "## B") == f"{line}\ntext\n"
    assert section(write_note, note, "B") == f"{line}\ntext\n"


@pytest.mark.parametrize("line", ["    ## B", "##B", "####### B", "#hashtag", "\t## B"])
def test_lines_that_are_not_headings(write_note, line):
    assert outline_headings(write_note, f"# A\n{line}\n") == ["# A"]


def test_a_closing_hash_without_a_space_is_part_of_the_text(write_note):
    note = "## C#\ntext\n## Notes ##\n"

    assert section(write_note, note, "C#") == "## C#\ntext\n"
    assert section(write_note, note, "Notes") == "## Notes ##\n"


def test_an_empty_heading_is_a_heading(write_note):
    note = "# A\n##\nunder the empty one\n"

    assert outline_headings(write_note, note) == ["# A", "##"]
    assert section(write_note, note, "##") == "##\nunder the empty one\n"


def test_a_crlf_note_reads_like_the_whole_read(vault_dir):
    (vault_dir / "crlf.md").write_bytes(b"# A\r\nalpha\r\n## B  \r\nbeta\r\n")
    whole = read("crlf.md")["content"]
    result = read("crlf.md", heading="## B")

    assert result["content"] in whole
    assert result["content"].replace("\r", "") == "## B  \nbeta\n"
    assert [e["heading"] for e in read("crlf.md", outline=True)["outline"]] == ["# A", "## B"]


def test_the_section_rule_ignores_a_crlf_lines_carriage_return():
    # Through the tool the read already gives "\n" (Python's text mode); the rule itself is
    # written for any caller, heading-scoped edits among them (#109), which may pass "\r\n".
    from obsidian_vault_mcp.vault import markdown_sections

    note = "# A\r\nalpha\r\n## B  \r\nbeta\r\n```\r\n# not\r\n```\r\n"
    sections = markdown_sections(note)

    assert [(s.line, s.heading) for s in sections] == [(1, "# A"), (3, "## B")]
    assert note[sections[1].start:sections[1].end] == "## B  \r\nbeta\r\n```\r\n# not\r\n```\r\n"


def test_only_a_newline_splits_lines(write_note):
    # str.splitlines() would split at U+2028 and form feed, and see a heading after each.
    note = "# A\nfirst # not a heading\nsecond\x0c# nor this\n"

    assert outline_headings(write_note, note) == ["# A"]
    assert section(write_note, note, "# A") == note


def test_a_skipped_level_still_nests(write_note):
    note = "# A\n### C\n## B\ntext\n# D\n"

    assert section(write_note, note, "# A") == "# A\n### C\n## B\ntext\n"
    assert section(write_note, note, "### C") == "### C\n"
    assert read(write_note(note), heading="## B")["heading"] == "# A > ## B"


def test_a_deeper_heading_before_the_first_shallower_one(write_note):
    note = "### Deep\ntext\n# Top\n"

    assert section(write_note, note, "### Deep") == "### Deep\ntext\n"
    assert read(write_note(note), heading="# Top")["heading"] == "# Top"


@pytest.mark.parametrize("ending", ["\n", ""])
def test_the_last_section_runs_to_the_end_of_the_note(write_note, ending):
    note = f"# A\n## B\nlast line{ending}"
    result = read(write_note(note), heading="## B")

    assert result["content"] == f"## B\nlast line{ending}"
    assert (result["start_line"], result["end_line"]) == (2, 3)


def test_an_empty_note(write_note):
    name = write_note("")

    assert read(name, outline=True)["outline"] == []
    assert read(name, outline=True)["size"] == {"chars": 0, "lines": 0}
    assert read(name, heading="# A")["error"].startswith("The note has no headings")
    assert read(name, heading="# A")["outline"] == []


def test_a_note_of_text_with_no_headings(write_note):
    name = write_note("first line\nsecond line\n")

    assert read(name, outline=True)["outline"] == []
    assert read(name, heading="## A") == {
        "error": "The note has no headings, so it has no sections to read", "path": name, "outline": [],
    }


def test_a_note_that_is_only_frontmatter(write_note):
    result = read(write_note("---\nstatus: active\n---\n"), outline=True)

    assert result["outline"] == []
    assert result["frontmatter"] == {"status": "active"}


# --- Naming a heading ---


NESTED = """# Guide
## Setup
guide setup
# Reference
## Setup
reference setup
### Linux
linux
"""


@pytest.mark.parametrize(
    "heading",
    ["# Guide > ## Setup", "Guide > Setup", "# Guide > Setup", "Guide > ## Setup"],
)
def test_a_path_from_a_parent_picks_one_of_two_repeats(write_note, heading):
    assert section(write_note, NESTED, heading) == "## Setup\nguide setup\n"


def test_a_path_may_skip_levels(write_note):
    assert section(write_note, NESTED, "# Reference > ### Linux") == "### Linux\nlinux\n"
    assert section(write_note, NESTED, "Reference > Setup > Linux") == "### Linux\nlinux\n"


def test_the_heading_as_written_must_match_its_level(write_note):
    result = read(write_note(NESTED), heading="### Setup")

    assert result["error"].startswith("No heading matches")


def test_a_heading_with_a_comma_or_a_slash_as_a_wiki_link_gives_it(write_note):
    note = "# Plan\n## Q3, Q4 / review\ntext\n"

    assert section(write_note, note, "Q3, Q4 / review") == "## Q3, Q4 / review\ntext\n"


def test_matching_is_case_sensitive(write_note):
    assert read(write_note(GUIDE), heading="## usage")["error"].startswith("No heading matches")


def test_a_heading_not_found_returns_the_outline(write_note):
    result = read(write_note(GUIDE), heading="## Missing")

    assert list(result) == ["error", "path", "outline"]
    assert result["path"] == "note.md"
    assert [e["heading"] for e in result["outline"]] == ["# Guide", "## Setup", "### Linux", "## Usage"]


def test_the_error_does_not_echo_the_heading(write_note):
    # The audit log keeps a read's error text; the caller already knows what it asked for.
    result = read(write_note(GUIDE), heading="## Quarterly salary review")

    assert "salary" not in result["error"]


def test_text_alone_at_two_levels_returns_the_matches(write_note):
    result = read(write_note(NESTED), heading="Setup")

    assert list(result) == ["error", "path", "matches"]
    assert result["error"].startswith("The heading matches 2 sections")
    assert result["matches"] == [
        {"heading": "# Guide > ## Setup", "line": 2, "chars": len("## Setup\nguide setup\n")},
        {"heading": "# Reference > ## Setup", "line": 5, "chars": len("## Setup\nreference setup\n### Linux\nlinux\n")},
    ]


def test_a_repeat_under_the_same_parent_says_no_path_tells_them_apart(write_note):
    note = "# Log\n## Entry\none\n## Entry\ntwo\n"
    result = read(write_note(note), heading="## Entry")

    assert result["error"].startswith("The heading matches 2 sections")
    assert "no path tells apart" in result["error"]
    assert [m["heading"] for m in result["matches"]] == ["# Log > ## Entry", "# Log > ## Entry"]


SKIPPED = "# Guide\n### Setup\nfirst\n## Other\n### Setup\nsecond\n"


def test_a_path_naming_every_level_wins_over_one_that_skips(write_note):
    name = write_note(SKIPPED)
    matches = read(name, heading="Setup")["matches"]

    assert [m["heading"] for m in matches] == ["# Guide > ### Setup", "# Guide > ## Other > ### Setup"]
    assert "no path tells apart" not in read(name, heading="Setup")["error"]
    assert read(name, heading="# Guide > ### Setup")["content"] == "### Setup\nfirst\n"
    assert read(name, heading="# Guide > ## Other > ### Setup")["content"] == "### Setup\nsecond\n"


def test_a_path_may_still_skip_levels_when_none_names_them_all(write_note):
    assert section(write_note, SKIPPED.replace("### Setup\nfirst\n", ""), "# Guide > ### Setup") == "### Setup\nsecond\n"


def test_a_heading_with_no_parent_repeated_deeper_says_no_path_tells_it_apart(write_note):
    name = write_note("## Notes\ntop\n# Day\n## Notes\nday\n")
    result = read(name, heading="## Notes")

    assert [m["heading"] for m in result["matches"]] == ["## Notes", "# Day > ## Notes"]
    assert "no path tells apart" in result["error"]
    assert read(name, heading="# Day > ## Notes")["content"] == "## Notes\nday\n"


def test_a_repeat_whose_path_is_too_long_to_pass_back_says_so(write_note):
    # Under a 500-character parent, a 500-character heading's path passes heading's cap.
    child = "## " + "C" * 500
    name = write_note(f"# {'P' * 500}\n{child}\na\n# Q\n{child}\nb\n")
    result = read(name, heading="C" * 500)

    assert result["matches"][0]["heading"] is None  # left out rather than sent: it couldn't come back
    assert result["matches"][1]["heading"] == f"# Q > {child}"
    assert "no path tells apart" in result["error"]


def test_a_repeat_lists_at_most_fifty_matches_and_stays_small(write_note):
    # Each match's path repeats the parent's heading: under a long parent with many children
    # the error would grow with both, so the list is capped and over-long paths left out.
    name = write_note("# " + "P" * 100_000 + "\n" + "## a\nx\n" * 50_000)
    started = time.perf_counter()
    reply = raw_read(name, heading="a")

    assert time.perf_counter() - started < 15
    assert len(reply) < 20_000
    result = json.loads(reply)
    assert result["error"].startswith("The heading matches 50000 sections; pass one of their headings from matches (the first 50)")
    assert len(result["matches"]) == 50 and all(m["heading"] is None for m in result["matches"])


SEPARATOR = "# Settings\n## General\ngeneral body\n# Settings > General\nother body\n## Menu > Preferences\nprefs\n"


def test_a_heading_whose_text_holds_the_separator_names_itself(write_note):
    name = write_note(SEPARATOR)

    assert read(name, heading="# Settings > General")["content"] == "# Settings > General\nother body\n## Menu > Preferences\nprefs\n"
    assert read(name, heading="## Menu > Preferences")["content"] == "## Menu > Preferences\nprefs\n"
    assert read(name, heading="# Settings > ## General")["content"] == "## General\ngeneral body\n"


def test_a_repeat_whose_path_holds_the_separator_says_no_path_tells_it_apart(write_note):
    # Split as a path, "# Top > ## A > B > ### x" would look for "B" under "## A".
    name = write_note("# Top\n## A > B\n### x\none\n# Other\n### x\ntwo\n")
    result = read(name, heading="### x")

    assert [m["heading"] for m in result["matches"]] == ["# Top > ## A > B > ### x", "# Other > ### x"]
    assert "no path tells apart" in result["error"]
    assert read(name, heading="# Other > ### x")["content"] == "### x\ntwo\n"


@pytest.mark.parametrize("space", [pytest.param(" ", id="no-break"), pytest.param("　", id="ideographic")])
def test_a_heading_ending_in_unicode_whitespace_reads_back(write_note, space):
    # The input model strips what a caller sends with str.strip(); headings are compared stripped alike.
    name = write_note(f"# Top\n## Foo{space}\nbody\n")
    written = read(name, outline=True)["outline"][1]["heading"]

    assert written == f"## Foo{space}"
    assert read(name, heading=written)["content"] == f"## Foo{space}\nbody\n"


def test_a_closing_run_before_unicode_whitespace_reads_back(write_note):
    # The closing '#'s are cut once the line is stripped, as the input is; else "Foo ##" != "Foo".
    name = write_note("# Top\n## Foo ## \nbody\n")
    written = read(name, outline=True)["outline"][1]["heading"]

    assert read(name, heading=written)["content"] == "## Foo ## \nbody\n"
    assert read(name, heading="Foo")["content"] == "## Foo ## \nbody\n"


def test_a_note_of_little_but_headings_gets_no_outline_bigger_than_itself(write_note):
    name = write_note("#\n" * 2_000)
    result = read(name, heading="## missing")

    assert "outline" not in result
    assert result["error"] == "No heading matches, and the outline would be bigger than the note: read the whole note"
    assert "outline" in read(write_note(GUIDE, "guide.md"), heading="## missing")


ROUND_TRIP = """---
tags: [x]
---
# Guide
intro
## Setup
guide setup
### Linux
linux
## Setup
second setup under the same parent
# Reference
## Setup
reference setup
## Usage
usage
# Appendix
### Setup
appendix setup
## Other
### Setup
other setup
## Plan > Do
plan and do
"""


def test_every_heading_the_outline_or_matches_shows_finds_its_entry(write_note):
    name = write_note(ROUND_TRIP)
    outline = read(name, outline=True)["outline"]
    assert len(outline) == 12

    for entry in outline:
        result = read(name, heading=entry["heading"])
        if "matches" in result:
            assert entry["line"] in [m["line"] for m in result["matches"]]
            candidates = result["matches"]
        else:
            assert result["start_line"] == entry["line"]
            assert len(result["content"]) == entry["chars"]
            candidates = []
        for match in candidates:
            again = read(name, heading=match["heading"])
            if "error" in again:
                assert "no path tells apart" in again["error"]
            else:
                assert again["start_line"] == match["line"]
                assert len(again["content"]) == match["chars"]


# --- Inputs ---


@pytest.mark.parametrize("heading", ["## a.*b", "## [draft] (v2)", "## a+b?"])
def test_pattern_characters_match_as_plain_text(write_note, heading):
    note = f"# Top\n{heading}\nmine\n## axxb\n## [d] v2\n## aab\n"

    assert section(write_note, note, heading) == f"{heading}\nmine\n"


def test_a_newline_inside_heading_matches_nothing(write_note):
    result = read(write_note(GUIDE), heading="## Setup\n## Usage")

    assert result["error"].startswith("No heading matches")


def test_a_path_with_an_empty_part_matches_nothing(write_note):
    result = read(write_note(GUIDE), heading="# Guide >  > ## Setup")

    assert result["error"].startswith("No heading matches")


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_heading_counts_as_not_given(write_note, blank):
    assert read(write_note(GUIDE), heading=blank) == read("note.md")


def test_an_over_long_heading_is_refused(write_note):
    with pytest.raises(ToolError) as excinfo:
        read(write_note(GUIDE), heading="#" + " x" * 600)

    assert "heading" in str(excinfo.value)


def test_heading_and_outline_together_are_refused(write_note):
    with pytest.raises(ToolError) as excinfo:
        read(write_note(GUIDE), heading="## Setup", outline=True)

    assert "Use only one of 'heading', 'outline', not several" in str(excinfo.value)


@pytest.mark.parametrize(
    "value",
    [pytest.param("maybe", id="string"), pytest.param(["x"], id="list"), pytest.param(2, id="number")],
)
def test_an_outline_that_is_not_a_boolean_is_refused(write_note, value):
    with pytest.raises(ToolError) as excinfo:
        read(write_note(GUIDE), outline=value)

    assert "outline" in str(excinfo.value)


@pytest.mark.parametrize("value", [pytest.param(5, id="number"), pytest.param(["## Setup"], id="list")])
def test_a_heading_that_is_not_a_string_is_refused(write_note, value):
    with pytest.raises(ToolError) as excinfo:
        read(write_note(GUIDE), heading=value)

    assert "heading" in str(excinfo.value)


@pytest.mark.parametrize(
    "note",
    [
        pytest.param("# a" + " " * 100_000 + "b\n", id="spaces-inside-a-heading"),
        pytest.param("# a" + " " * 100_000 + "#x\n", id="spaces-before-a-hash"),
        pytest.param("a | b\n|" + " " * 100_000 + "x\n", id="a-long-table-delimiter"),
        pytest.param("#\n" * 100_000, id="a-hundred-thousand-headings"),
    ],
)
def test_a_crafted_note_is_read_in_time(write_note, note):
    # Python's re backtracks: a pattern that backtracks over a run of whitespace, or a
    # search for each section's end among all the headings after it, takes minutes on
    # these. Linear, they take a second or two, so the bound leaves room for a slow runner.
    name = write_note(note)
    started = time.perf_counter()
    outline = read(name, outline=True)
    missing = read(name, heading="## missing")
    assert time.perf_counter() - started < 15
    assert "outline" in outline
    assert "outline" in missing or "bigger than the note" in missing["error"]


def test_a_path_outside_the_vault_is_refused_as_before(write_note):
    result = read("../outside.md", heading="# A")

    assert "error" in result and "outline" not in result


def test_a_missing_note_is_reported_as_before(vault_dir):
    assert read("missing.md", outline=True) == read("missing.md")


# --- Files that are not Markdown ---


@pytest.mark.parametrize("arguments", [{"heading": "# A"}, {"outline": True}])
def test_headings_exist_only_in_markdown_notes(vault_dir, arguments):
    (vault_dir / "notes.txt").write_text("# A\ntext\n", encoding="utf-8")

    assert read("notes.txt", **arguments) == {"error": "Headings exist only in Markdown notes", "path": "notes.txt"}


@pytest.mark.parametrize("name", ["UPPER.MD", "long.markdown", "Mixed.Md"])
def test_markdown_by_its_suffix_in_any_case(write_note, name):
    assert section(lambda text: write_note(text, name), "# A\ntext\n", "# A") == "# A\ntext\n"


@pytest.fixture
def extracted_md(vault_dir):
    content_extractors._content_extractors.clear()
    register_content_extractor(lambda relative_path, path: "# Extracted\ntext\n")
    (vault_dir / "scan.md").write_bytes(b"\xff\xfe not utf-8")
    yield "scan.md"
    content_extractors._content_extractors.clear()


def test_extracted_text_has_no_headings(extracted_md):
    assert read(extracted_md)["metadata"]["extracted"] is True
    assert read(extracted_md, outline=True)["error"] == "Headings exist only in Markdown notes"


# --- The schema, the description and the audit ---


def test_heading_and_outline_are_in_the_tool_schema_and_optional(vault_dir):
    tool = next(t for t in asyncio.run(server.mcp.list_tools()) if t.name == "vault_read")
    schema = tool.inputSchema

    assert {"type": "string"} in schema["properties"]["heading"]["anyOf"]
    assert schema["properties"]["heading"]["default"] is None
    assert schema["properties"]["outline"]["type"] == "boolean"
    assert schema["properties"]["outline"]["default"] is False
    assert schema["required"] == ["path"]


def test_the_description_names_both_parameters_briefly_and_without_numbers(vault_dir):
    tool = next(t for t in asyncio.run(server.mcp.list_tools()) if t.name == "vault_read")

    assert tool.description.startswith(
        "Read a file from the Obsidian vault, returning content, metadata, and parsed YAML frontmatter. "
    )
    assert "Pass heading" in tool.description and "Set outline=true" in tool.description
    assert len(tool.description) < 2048
    assert not any(character.isdigit() for character in tool.description)


@pytest.fixture
def audit_log(tmp_path, monkeypatch, vault_dir):
    log_path = tmp_path / "audit" / "reads.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(log_path))
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", True)
    token = context.set_request_context(principal="test-principal", request_id="req-1", client="pytest")
    yield log_path
    context.reset_request_context(token)


def test_the_audit_records_a_section_read_and_a_heading_not_found(write_note, audit_log):
    name = write_note(GUIDE)
    read(name, heading="## Setup")
    read(name, outline=True)
    read(name, heading="## Quarterly salary review")

    records = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines() if line]
    assert [r["operation"] for r in records] == ["vault_read"] * 3
    assert [r["target_path"] for r in records] == [name] * 3
    assert [r["operation_status"] for r in records] == ["success", "success", "error"]
    assert "salary" not in audit_log.read_text(encoding="utf-8")
