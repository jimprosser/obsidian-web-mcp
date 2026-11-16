"""VAULT_PATH reached through a symlink.

Resolved paths (resolve_vault_path, ripgrep's output, a directory walk under a
resolved search path) must line up with config.VAULT_PATH, or every relative_to()
against it fails and the file is silently skipped. Each test runs in a fresh
interpreter so VAULT_PATH is read from the environment the way server startup reads it.
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

SEARCH = (
    "import json, shutil, sys\n"
    "from obsidian_vault_mcp import config\n"
    "from obsidian_vault_mcp.tools import search\n"
    "if sys.argv[1] == 'python':\n"
    "    shutil.which = lambda name: None\n"
    "print(json.dumps({'vault_path': str(config.VAULT_PATH),\n"
    "                  'result': json.loads(search.vault_search('needle', path_prefix='Projects'))}))\n"
)


@pytest.fixture
def linked_vault(tmp_path):
    real = tmp_path / "real-vault"
    (real / "Projects").mkdir(parents=True)
    (real / "Projects" / "note.md").write_text("hello needle\n")
    link = tmp_path / "vault-link"
    link.symlink_to(real, target_is_directory=True)
    return real, link


def run_search(vault_path, backend):
    env = {k: v for k, v in os.environ.items() if not k.startswith("VAULT_")}
    env["VAULT_PATH"] = str(vault_path)
    proc = subprocess.run([sys.executable, "-c", SEARCH, backend], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_config_resolves_a_symlinked_vault_path(linked_vault):
    real, link = linked_vault
    assert run_search(link, "python")["vault_path"] == str(real.resolve())


@pytest.mark.parametrize("backend", [
    "python",
    pytest.param("ripgrep", marks=pytest.mark.skipif(not shutil.which("rg"), reason="ripgrep not installed")),
])
def test_path_prefix_search_through_a_symlinked_vault(linked_vault, backend):
    _, link = linked_vault
    result = run_search(link, backend)["result"]
    assert [(m["path"], m["match_type"]) for m in result["results"]] == [("Projects/note.md", "content")], result
