"""Regression tests: vault_search must not let a query be parsed as a ripgrep flag.

A query beginning with "-" (e.g. "--pre=/bin/sh", ripgrep's preprocessor flag,
which executes an arbitrary program per searched file) was passed to ripgrep as a
bare positional argument. ripgrep parsed it as an OPTION, yielding argv option
injection and remote code execution via the vault_search query argument. The fix
passes the query with `-e`, which forces ripgrep to treat it as a search pattern.
"""

import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from obsidian_vault_mcp.tools import search as search_mod


def test_query_is_passed_with_dash_e(monkeypatch, tmp_path):
    """The query must be guarded by `-e` so a leading-dash value can't be a flag."""
    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(search_mod.subprocess, "run", fake_run)

    malicious = "--pre=/bin/sh"
    search_mod._search_ripgrep(
        malicious, tmp_path, file_pattern="*.md", max_results=10, context_lines=2
    )

    cmd = captured["cmd"]
    # The query must appear immediately after a `-e`, never as a bare token.
    assert "-e" in cmd, f"query not guarded by -e: {cmd}"
    assert cmd[cmd.index(malicious) - 1] == "-e", (
        f"query must be preceded by -e to neutralize leading-dash flags: {cmd}"
    )
    # And the search path stays a positional after the guarded query.
    assert cmd[-1] == str(tmp_path)


@pytest.mark.skipif(shutil.which("rg") is None, reason="ripgrep not installed")
def test_leading_dash_query_is_treated_as_literal_pattern(tmp_path, monkeypatch):
    """End-to-end: a '--pre=...'-style query is searched literally, not executed."""
    monkeypatch.setattr(search_mod.config, "VAULT_PATH", tmp_path)
    sentinel = tmp_path / "PWNED"
    (tmp_path / "note.md").write_text("a line containing --pre=/bin/sh literally\n")

    # Reuse the real builder so we exercise the exact argv the server sends.
    matches = search_mod._search_ripgrep(
        "--pre=/bin/sh", tmp_path, file_pattern="*.md", max_results=10, context_lines=1
    )

    # No preprocessor program ran...
    assert not sentinel.exists(), "ripgrep executed the query as a --pre program"
    # ...and the query matched as a literal substring of the note.
    assert any("--pre=/bin/sh" in m.get("match_context", "") for m in matches), (
        f"leading-dash query was not treated as a literal pattern: {matches}"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
