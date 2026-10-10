"""vault_semantic_search: the optional, built-in semantic-search extension.

Most cases run the real extension through the lifecycle serve() drives (register_tools,
before_indexes_start, after_indexes_start, shutdown) and call the registered tool through
FastMCP, with one stand-in: `sentence_transformers` resolves to a bag-of-words encoder
(tests/_semantic_fake.py), so CI needs numpy but not the model. The SQLite index, the read
guard, the frontmatter index's change listener and the reconcile loop are the real ones.

serve() itself is covered for the switch: off registers and imports nothing, on refuses to
start without the extra or with the index inside the vault, and on starts a real server in
a child process. The last test uses the real model and runs only where the `semantic`
extra is installed.
"""

import asyncio
import importlib.util
import json
import os
import sqlite3
import stat
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from obsidian_vault_mcp import audit, config, server
from obsidian_vault_mcp.frontmatter_index import FrontmatterIndex

from . import _semantic_fake
from ._live_server import call_tool_over_http, list_tools_over_http, live_server

HAVE_MODEL = importlib.util.find_spec("sentence_transformers") is not None
REQUIRE = os.environ.get("VAULT_TEST_REQUIRE_TOOLS", "").strip().lower() in {"1", "true", "yes", "on"}
TOOL = "vault_semantic_search"


@pytest.fixture
def fake_model(monkeypatch):
    monkeypatch.setitem(sys.modules, "sentence_transformers", _semantic_fake.module())


def _call(mcp, **arguments) -> dict:
    result = asyncio.run(mcp.call_tool(TOOL, arguments))
    if isinstance(result, tuple):
        result = result[0]
    return json.loads("".join(getattr(block, "text", "") for block in result))


def _indexed_paths() -> set[str]:
    with sqlite3.connect(config.VAULT_SEMANTIC_DB_PATH) as conn:
        return {row[0] for row in conn.execute("SELECT path FROM embeddings")}


@contextmanager
def running():
    """The extension started the way serve() starts it, on a fresh FastMCP."""
    from obsidian_vault_mcp.semantic.extension import SemanticExtension

    mcp = FastMCP("semantic-test")
    frontmatter_index = FrontmatterIndex()
    ext = SemanticExtension()
    ext.register_tools(mcp)
    ext.before_indexes_start(frontmatter_index)
    frontmatter_index.rebuild()  # what start() does before it watches; no watcher thread here
    ext.after_indexes_start(frontmatter_index)

    def changed(path: Path) -> None:
        """Deliver a change the way the watcher does: the frontmatter index's own flush."""
        frontmatter_index._pending_paths.add(str(path))
        frontmatter_index._flush_pending()

    try:
        yield SimpleNamespace(
            ext=ext,
            search=lambda **arguments: _call(mcp, **arguments),
            changed=changed,
            reconcile=ext._index.reconcile,
        )
    finally:
        ext.shutdown()


@pytest.fixture
def semantic(vault_dir, fake_model):
    with running() as s:
        yield s


def _paths(result: dict) -> list[str]:
    assert "error" not in result, result
    return [hit["path"] for hit in result["results"]]


# --- the switch, through serve() --------------------------------------------------------

@pytest.fixture
def quiet_serve(vault_dir, monkeypatch):
    """serve() with no index, no uvicorn and no atexit; returns a list that records a start."""
    import uvicorn

    ran = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: ran.append(True))
    monkeypatch.setattr(server, "VAULT_PATH", vault_dir)
    monkeypatch.setattr(server.frontmatter_index, "start", lambda: None)
    monkeypatch.setattr(server.frontmatter_index, "stop", lambda: None)
    monkeypatch.setattr(server.atexit, "register", lambda fn, *a, **k: None)
    return ran


def _semantic_modules() -> list[str]:
    return [name for name in sys.modules if name.startswith("obsidian_vault_mcp.semantic")]


def test_off_by_default_nothing_is_imported_or_registered(quiet_serve, monkeypatch):
    for name in _semantic_modules():
        monkeypatch.delitem(sys.modules, name)

    server.serve()

    assert quiet_serve == [True]
    assert server.mcp._tool_manager.get_tool(TOOL) is None
    assert _semantic_modules() == []


def test_on_without_the_extra_refuses_to_start(quiet_serve, monkeypatch, caplog):
    monkeypatch.setattr(config, "VAULT_SEMANTIC_SEARCH", "1")
    monkeypatch.setitem(sys.modules, "sentence_transformers", None)  # as if not installed

    with pytest.raises(SystemExit) as exited:
        server.serve()

    assert exited.value.code == 1
    assert quiet_serve == []
    assert "obsidian-web-mcp[semantic]" in caplog.text
    assert server.mcp._tool_manager.get_tool(TOOL) is None


@pytest.mark.parametrize("via_symlink", [False, True], ids=["direct", "through-a-symlink"])
def test_on_with_the_index_inside_the_vault_refuses_to_start(
    quiet_serve, fake_model, vault_dir, tmp_path, monkeypatch, caplog, via_symlink
):
    parent = vault_dir / "index"
    if via_symlink:
        parent = tmp_path / "looks-outside"
        parent.symlink_to(vault_dir)
    monkeypatch.setattr(config, "VAULT_SEMANTIC_SEARCH", "1")
    monkeypatch.setattr(config, "VAULT_SEMANTIC_DB_PATH", parent / "embeddings.db")

    with pytest.raises(SystemExit) as exited:
        server.serve()

    assert exited.value.code == 1
    assert quiet_serve == []
    assert "VAULT_SEMANTIC_DB_PATH resolves inside the vault" in caplog.text
    assert not (vault_dir / "index").exists() and not (vault_dir / "embeddings.db").exists()


def test_a_value_that_is_neither_on_nor_off_stops_startup(vault_dir, monkeypatch):
    monkeypatch.setattr(config, "VAULT_SEMANTIC_SEARCH", "ture")

    with pytest.raises(ValueError, match="VAULT_SEMANTIC_SEARCH"):
        config.validate_config()


# --- the tool --------------------------------------------------------------------------

def test_registered_as_a_read_and_audited_like_one(semantic, tmp_path, monkeypatch):
    assert audit.operation_kind(TOOL) == "read"
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(log))

    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", False)
    semantic.search(query="test note")
    assert not log.exists(), "a read stays out of the log while reads are excluded"

    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", True)
    semantic.search(query="test note")
    (record,) = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert record["operation"] == TOOL
    assert record["operation_status"] == "success"
    assert "test note" not in json.dumps(record), "the query is not logged"


@pytest.mark.parametrize("via", ["watcher", "reconcile"])
def test_adding_changing_and_deleting_a_note_updates_results(semantic, vault_dir, via):
    note = vault_dir / "animals" / "stripes.md"

    def sync():
        semantic.changed(note) if via == "watcher" else semantic.reconcile()

    note.parent.mkdir()
    note.write_text("# Stripes\n\nzebra stripes\n", encoding="utf-8")
    sync()
    hits = semantic.search(query="zebra")["results"]
    assert [h["path"] for h in hits] == ["animals/stripes.md"]
    assert hits[0]["title"] == "Stripes" and hits[0]["excerpt"] == "zebra stripes"

    note.write_text("# Necks\n\ngiraffe necks\n", encoding="utf-8")
    later = time.time() + 10
    os.utime(note, (later, later))
    sync()
    assert _paths(semantic.search(query="zebra")) == []
    assert _paths(semantic.search(query="giraffe")) == ["animals/stripes.md"]

    note.unlink()
    sync()
    assert _paths(semantic.search(query="giraffe")) == []
    assert "animals/stripes.md" not in _indexed_paths()


def test_path_prefix_limits_results_and_cannot_widen_them(semantic, vault_dir):
    for folder in ("work", "work_old", "home"):
        (vault_dir / folder).mkdir()
        (vault_dir / folder / "plan.md").write_text("quarterly plan\n", encoding="utf-8")
    semantic.reconcile()

    assert _paths(semantic.search(query="quarterly plan", path_prefix="work/")) == ["work/plan.md"]
    # LIKE wildcards are literal: as a wildcard, "_" would also match the "/" of work/plan.md.
    assert _paths(semantic.search(query="quarterly plan", path_prefix="work_")) == ["work_old/plan.md"]
    # A prefix is matched against vault-relative paths only.
    for prefix in ("%", "../", "/"):
        assert _paths(semantic.search(query="quarterly plan", path_prefix=prefix)) == [], prefix


@pytest.mark.parametrize(
    "arguments",
    [
        {"query": ""},
        {"query": "x" * 501},
        {"query": "plan", "max_results": 0},
        {"query": "plan", "max_results": 21},
        {"query": "plan", "min_score": -0.1},
        {"query": "plan", "min_score": 1.5},
        {"query": "plan", "path_prefix": "p" * 501},
    ],
)
def test_out_of_bounds_arguments_are_refused(semantic, arguments):
    with pytest.raises(ToolError):
        semantic.search(**arguments)


# --- what the index may read -------------------------------------------------------------

SECRET = "hunter2"


def _refused(kind: str, vault: Path, outside: Path, name: str) -> list[str]:
    """Create a note the read guard refuses; return the vault paths that must never surface."""
    content = f"quokka {SECRET}\n"
    if kind == "outside_symlink":
        target = outside / f"{name}-outside.md"
        target.write_text(content, encoding="utf-8")
        (vault / f"{name}.md").symlink_to(target)
        return [f"{name}.md"]
    if kind == "inside_symlink":
        target = vault / f"{name}-target.md"
        target.write_text("quokka\n", encoding="utf-8")
        (vault / f"{name}.md").symlink_to(target)
        return [f"{name}.md"]
    if kind == "symlinked_dir":
        real = outside / f"{name}-dir"
        real.mkdir()
        (real / "note.md").write_text(content, encoding="utf-8")
        (vault / f"{name}-dir").symlink_to(real)
        return [f"{name}-dir/note.md"]
    if kind == "outside_hardlink":
        source = outside / f"{name}-outside.md"
        source.write_text(content, encoding="utf-8")
        os.link(source, vault / f"{name}.md")
        return [f"{name}.md"]
    if kind == "inside_hardlink":
        (vault / f"{name}-twin.md").write_text(content, encoding="utf-8")
        os.link(vault / f"{name}-twin.md", vault / f"{name}.md")
        return [f"{name}.md", f"{name}-twin.md"]
    if kind == "excluded_dir":
        # A name without a dot, so this is the EXCLUDED_DIRS rule and not the dot rule
        # (the built-in exclusions all start with a dot; dot_dir covers those).
        (vault / "Private").mkdir(exist_ok=True)
        (vault / "Private" / f"{name}.md").write_text(content, encoding="utf-8")
        return [f"Private/{name}.md"]
    if kind == "dot_dir":
        (vault / ".hidden").mkdir(exist_ok=True)
        (vault / ".hidden" / f"{name}.md").write_text(content, encoding="utf-8")
        return [f".hidden/{name}.md"]
    if kind == "oversize":
        padding = "quokka " * (config.MAX_CONTENT_SIZE // 7 + 1)
        (vault / f"{name}.md").write_text(f"{content}{padding}", encoding="utf-8")
        return [f"{name}.md"]
    raise AssertionError(kind)


@pytest.mark.parametrize(
    "kind",
    ["outside_symlink", "inside_symlink", "symlinked_dir", "outside_hardlink",
     "inside_hardlink", "excluded_dir", "dot_dir", "oversize"],
)
def test_refused_files_are_never_indexed_or_returned(vault_dir, tmp_path, fake_model, monkeypatch, kind):
    monkeypatch.setattr(config, "EXCLUDED_DIRS", config.EXCLUDED_DIRS | {"Private"})
    outside = tmp_path / "outside"
    outside.mkdir()
    (vault_dir / "control.md").write_text("quokka habitat\n", encoding="utf-8")
    refused = _refused(kind, vault_dir, outside, "early")  # there when the index first builds

    with running() as s:
        late = _refused(kind, vault_dir, outside, "late")  # arrives while it runs
        for rel in late:
            s.changed(vault_dir / rel)  # the watcher's path
        s.reconcile()  # the periodic floor's path
        result = s.search(query="quokka", min_score=0.0, max_results=20)

        assert "control.md" in _paths(result), "negative control: the query finds a readable note"
        for rel in refused + late:
            assert rel not in _paths(result), rel
            assert rel not in _indexed_paths(), rel
        assert SECRET not in json.dumps(result)


@pytest.mark.parametrize("cleanup", ["watcher", "reconcile"])
@pytest.mark.parametrize("how", ["hardlinked", "symlinked_out", "deleted"])
def test_a_result_that_became_unreadable_is_dropped_at_query_time(semantic, vault_dir, tmp_path, how, cleanup):
    note = vault_dir / "plans.md"
    note.write_text("ocelot plans\n", encoding="utf-8")
    semantic.changed(note)
    assert _paths(semantic.search(query="ocelot")) == ["plans.md"], "negative control"

    # No event and no reconcile: only the query-time check stands between the row and the caller.
    if how == "hardlinked":
        os.link(note, tmp_path / "second-name.md")
    elif how == "symlinked_out":
        outside = tmp_path / "outside.md"
        outside.write_text("ocelot plans\n", encoding="utf-8")
        note.unlink()
        note.symlink_to(outside)
    else:
        note.unlink()

    assert "plans.md" in _indexed_paths()
    assert _paths(semantic.search(query="ocelot")) == []

    # Then the row itself goes, whichever path notices first: the file still exists in two
    # of the three cases, so "gone from disk" alone would keep it.
    semantic.changed(note) if cleanup == "watcher" else semantic.reconcile()
    assert "plans.md" not in _indexed_paths()


# --- the index files --------------------------------------------------------------------

# The embeddings table as an index built before this extension has it: the layout it creates too.
EMBEDDINGS_TABLE = (
    "CREATE TABLE embeddings (path TEXT PRIMARY KEY, embedding BLOB, mtime REAL, "
    "title TEXT, excerpt TEXT, updated_at REAL)"
)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_the_index_is_owner_only_and_tightens_a_looser_one(vault_dir, fake_model):
    db = config.VAULT_SEMANTIC_DB_PATH
    # An earlier, looser install that left its files behind: directory 0755, database 0644,
    # and a WAL that still holds writes, 0644 too. (SQLite recreates empty leftovers with
    # the database's mode by itself; a WAL with content it keeps, mode and all.)
    db.parent.mkdir(parents=True)
    os.chmod(db.parent, 0o755)
    earlier = sqlite3.connect(db)
    earlier.execute("PRAGMA journal_mode=WAL")
    earlier.execute(EMBEDDINGS_TABLE)
    earlier.commit()
    try:
        for path in (db, Path(f"{db}-wal"), Path(f"{db}-shm")):
            assert path.stat().st_size > 0, path
            os.chmod(path, 0o644)

        with running():
            assert _mode(db.parent) == 0o700
            for path in (db, Path(f"{db}-wal"), Path(f"{db}-shm")):
                assert _mode(path) == 0o600, path
    finally:
        earlier.close()


def test_a_new_index_is_created_owner_only(vault_dir, fake_model):
    db = config.VAULT_SEMANTIC_DB_PATH
    assert not db.parent.exists()

    with running():
        assert _mode(db.parent) == 0o700
        for path in (db, Path(f"{db}-wal"), Path(f"{db}-shm")):
            assert _mode(path) == 0o600, path


def test_an_existing_index_is_reused_without_embedding_again(vault_dir, fake_model):
    """An index written with the same table layout is used as it is: only changed notes
    are embedded again. That is what lets an existing index switch to this one."""
    db = config.VAULT_SEMANTIC_DB_PATH
    db.parent.mkdir(parents=True)
    mtime = (vault_dir / "test-note.md").stat().st_mtime
    vector = _semantic_fake.WordEncoder().encode("test note").astype("float32").tobytes()
    with sqlite3.connect(db) as conn:
        conn.execute(EMBEDDINGS_TABLE)
        conn.execute(
            "INSERT INTO embeddings VALUES (?, ?, ?, ?, ?, ?)",
            ("test-note.md", vector, mtime, "Kept title", "kept excerpt", 1.0),
        )

    with running() as s:
        (hit,) = [h for h in s.search(query="test note", min_score=0.0)["results"] if h["path"] == "test-note.md"]

    assert (hit["title"], hit["excerpt"]) == ("Kept title", "kept excerpt")
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT updated_at FROM embeddings WHERE path = 'test-note.md'").fetchone() == (1.0,)


# --- the reconcile loop -----------------------------------------------------------------

def test_the_reconcile_loop_heals_a_missed_event_and_stops_on_shutdown(vault_dir, fake_model, monkeypatch):
    from obsidian_vault_mcp.semantic import extension

    monkeypatch.setattr(extension, "RECONCILE_INTERVAL", 0.05)
    with running() as s:
        (vault_dir / "missed.md").write_text("okapi\n", encoding="utf-8")  # no event delivered
        deadline = time.time() + 10
        while "missed.md" not in _indexed_paths():
            assert time.time() < deadline, "the loop never picked up the note"
            time.sleep(0.05)
        thread = s.ext._reconcile

    assert not thread.is_alive()
    assert s.ext._index._db is None


# --- a real server process --------------------------------------------------------------

BOOTSTRAP = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})
from tests._semantic_fake import install
install()
EXTENSIONS = ()
"""


def test_switched_on_the_server_serves_the_tool(tmp_path):
    """serve() in its own process, as deployed: the switch, the default index location under
    HOME, the tool over MCP/HTTP with the bearer token, and its audit record."""
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "stripes.md").write_text("zebra stripes\n", encoding="utf-8")
    (vault / "taxes.md").write_text("estimated taxes\n", encoding="utf-8")
    log = tmp_path / "audit.jsonl"
    env = {"VAULT_SEMANTIC_SEARCH": "true", "VAULT_AUDIT_LOG_PATH": str(log), "VAULT_AUDIT_LOG_INCLUDE_READS": "on"}

    with live_server(tmp_path, vault, env, bootstrap=BOOTSTRAP) as (base_url, _log):
        tools = list_tools_over_http(base_url)
        result = call_tool_over_http(base_url, TOOL, {"query": "zebra"})

    assert TOOL in tools
    assert _paths(result) == ["stripes.md"]
    db = tmp_path / "home" / ".local" / "share" / "vault-mcp" / "embeddings.db"
    assert _mode(db) == 0o600 and _mode(db.parent) == 0o700
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [r["operation"] for r in records] == [TOOL]


def test_the_real_model_ranks_by_meaning(tmp_path):
    """The `semantic` extra end to end: the real model in a real server, no stand-in."""
    if not HAVE_MODEL:
        if REQUIRE:
            pytest.fail("sentence-transformers missing under VAULT_TEST_REQUIRE_TOOLS=1")
        pytest.skip("the semantic extra is not installed")
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "pets.md").write_text("# Puppy care\n\nGrooming a puppy, choosing kibble, and house training.\n")
    (vault / "taxes.md").write_text("# Estimated taxes\n\nQuarterly payments and deductions for a small business.\n")
    (vault / "garden.md").write_text("# Spring garden\n\nPlanting tomatoes and pruning roses before the last frost.\n")
    # The child's HOME is a temp dir; point it at the developer's model cache.
    env = {"VAULT_SEMANTIC_SEARCH": "1", "HF_HOME": os.environ.get("HF_HOME", str(Path.home() / ".cache" / "huggingface"))}
    if "HF_HUB_OFFLINE" in os.environ:
        env["HF_HUB_OFFLINE"] = os.environ["HF_HUB_OFFLINE"]

    with live_server(tmp_path, vault, env) as (base_url, _log):
        result = call_tool_over_http(base_url, TOOL, {"query": "what should I feed my dog", "min_score": 0.0})

    assert _paths(result)[0] == "pets.md", result
    db = tmp_path / "home" / ".local" / "share" / "vault-mcp" / "embeddings.db"
    with sqlite3.connect(db) as conn:
        columns = [(row[1], row[2], row[5]) for row in conn.execute("PRAGMA table_info(embeddings)")]
        lengths = {row[0] for row in conn.execute("SELECT length(embedding) FROM embeddings")}
    assert columns == [
        ("path", "TEXT", 1), ("embedding", "BLOB", 0), ("mtime", "REAL", 0),
        ("title", "TEXT", 0), ("excerpt", "TEXT", 0), ("updated_at", "REAL", 0),
    ]
    assert lengths == {384 * 4}, "all-MiniLM-L6-v2 vectors: 384 float32 values"
