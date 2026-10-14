"""Embedding index for vault_semantic_search.

Each .md note is embedded whole with sentence-transformers (all-MiniLM-L6-v2) and stored in
SQLite, so the index survives restarts. A query is compared against every stored vector
(brute-force cosine similarity), fast enough for a personal vault of a few thousand notes.

Every file the index reads passes the read tools' guard (_readable_note), and so does every
result before it is returned. The database holds an excerpt of every note, so it is created
0600 in a 0700 directory.
"""

import logging
import os
import sqlite3
import threading
import time
from pathlib import Path

import numpy as np

from .. import config
from ..tools.search import _iter_vault_files
from ..vault import resolve_vault_read_path

logger = logging.getLogger(__name__)

# The model and the table layout are the index's compatibility contract: an index written
# with them is reused as it is. Changing either means embedding every note again.
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

_UPSERT = """
    INSERT INTO embeddings (path, embedding, mtime, title, excerpt, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(path) DO UPDATE SET
        embedding = excluded.embedding, mtime = excluded.mtime, title = excluded.title,
        excerpt = excluded.excerpt, updated_at = excluded.updated_at
"""
# Every write stores what it read, with the mtime it read. A read that lands after a newer
# one (a slow reconcile pass, a late watcher callback) leaves a row whose mtime differs from
# the file's, and the next pass re-embeds any such note, so the index converges within one
# interval whatever the order. An mtime is not a version: a note restored from a backup
# goes back in time, which is why the pass compares for difference, not for newer.


def _blob_to_vector(blob: bytes) -> np.ndarray:
    return np.frombuffer(blob, dtype=np.float32)


def _vector_to_blob(vec: np.ndarray) -> bytes:
    return vec.astype(np.float32).tobytes()


def _extract_title(content: str, filename: str) -> str:
    """Extract first H1 heading or fall back to filename stem."""
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("# ") and not stripped.startswith("## "):
            return stripped[2:].strip()
    return Path(filename).stem


def _extract_excerpt(content: str, max_sentences: int = 3) -> str:
    """Extract opening sentences from content body (after frontmatter)."""
    lines = content.split("\n")

    body_start = 0
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                body_start = i + 1
                break

    sentences = []
    for line in lines[body_start:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if sentences:
                break
            continue
        sentences.append(stripped)
        if len(sentences) >= max_sentences:
            break

    return " ".join(sentences)[:500]


def _readable_note(rel: str) -> Path | None:
    """The note's resolved path when the index may read it, otherwise None.

    The read tools' guard (resolve_vault_read_path: nothing outside the vault, no dot
    components, no hardlinks) plus the rules of vault_search's walk: no excluded directory,
    no symlink anywhere below the root. Only .md notes up to MAX_CONTENT_SIZE.
    """
    if Path(rel).suffix != ".md" or config.EXCLUDED_DIRS & set(Path(rel).parts):
        return None
    try:
        path = resolve_vault_read_path(rel)
        if path != config.VAULT_PATH.resolve() / rel:
            return None
        if path.stat().st_size > config.MAX_CONTENT_SIZE:
            return None
    except (ValueError, OSError):
        return None
    return path


def _tighten_files(db_path: Path) -> None:
    """Create the database 0600 in a 0700 directory, the way the OAuth store does.

    SQLite creates the WAL and shared-memory files with the database's mode, but keeps the
    mode of ones an earlier, looser install left behind, so those are tightened here.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(db_path.parent, 0o700)
    os.close(os.open(db_path, os.O_RDWR | os.O_CREAT, 0o600))
    for path in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm")):
        if path.exists():
            os.chmod(path, 0o600)


class EmbeddingIndex:
    """Thread-safe embedding index backed by SQLite."""

    def __init__(self) -> None:
        self._model = None
        # Guards self._db, which stop() closes and clears while callbacks may be in flight.
        self._lock = threading.Lock()
        self._reconcile_lock = threading.Lock()
        self._db: sqlite3.Connection | None = None

    def start(self) -> None:
        """Open the database, load the embedding model, and bring the index up to date."""
        t0 = time.monotonic()

        # Resolved first, so a symlinked path tightens the real directory and WAL files.
        db_path = config.VAULT_SEMANTIC_DB_PATH.expanduser().resolve()
        _tighten_files(db_path)
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS embeddings (
                path TEXT PRIMARY KEY,
                embedding BLOB,
                mtime REAL,
                title TEXT,
                excerpt TEXT,
                updated_at REAL
            )
        """)
        self._db.commit()

        # Downloaded from Hugging Face on first start, then loaded from the local cache.
        from sentence_transformers import SentenceTransformer
        self._model = SentenceTransformer(EMBEDDING_MODEL)

        logger.info("Embedding model loaded in %.2fs", time.monotonic() - t0)

        self.reconcile()

    def stop(self) -> None:
        """Close the database. Work still in flight then finds it closed and does nothing."""
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    def reconcile(self) -> None:
        """Embed notes new or modified since the last pass; drop ones gone or refused.

        Safe to call repeatedly; a call made while a pass is running returns at once.
        """
        if self._db is None or self._model is None:
            return
        if not self._reconcile_lock.acquire(blocking=False):
            return
        try:
            self._reconcile_impl()
        finally:
            self._reconcile_lock.release()

    def _reconcile_impl(self) -> None:
        t0 = time.monotonic()

        with self._lock:
            if self._db is None:
                return
            db_mtimes = dict(self._db.execute("SELECT path, mtime FROM embeddings").fetchall())

        to_embed = []
        current_paths = set()
        for file_path in _iter_vault_files(config.VAULT_PATH, "*.md"):
            rel = str(file_path.relative_to(config.VAULT_PATH))
            path = _readable_note(rel)
            if path is None:
                continue
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            current_paths.add(rel)
            if rel not in db_mtimes or mtime != db_mtimes[rel]:
                to_embed.append((rel, path, mtime))

        # Rows for notes gone or now refused (an index built without the guard can hold
        # those). One that is readable again by now comes back with its watcher event or
        # the next pass.
        stale = set(db_mtimes) - current_paths
        removed = 0
        if stale:
            with self._lock:
                if self._db is None:
                    return
                for rel in stale:
                    self._db.execute("DELETE FROM embeddings WHERE path = ?", (rel,))
                    removed += 1
                self._db.commit()

        embedded = self._ingest(to_embed)
        logger.info(
            "Embedding index reconciled in %.2fs: %d embedded, %d removed, %d notes",
            time.monotonic() - t0, embedded, removed, len(current_paths),
        )

    def _ingest(self, notes: list[tuple[str, Path, float]]) -> int:
        """Read, embed and store notes the read guard admitted, given as (rel, path, mtime).

        The one way content enters the index, for the watcher and reconcile alike. Returns
        how many notes were embedded.
        """
        contents = []
        rows = []
        for rel, path, mtime in notes:
            try:
                with open(path, "rb") as f:
                    data = f.read(config.MAX_CONTENT_SIZE + 1)
                # The note can grow between the guard's size check and this read.
                if len(data) > config.MAX_CONTENT_SIZE:
                    continue
                content = data.decode("utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            contents.append(content)
            rows.append((rel, mtime, _extract_title(content, rel), _extract_excerpt(content)))
        if not contents:
            return 0

        vectors = self._model.encode(contents, show_progress_bar=False, normalize_embeddings=True)
        with self._lock:
            if self._db is None:
                return 0
            for (rel, mtime, title, excerpt), vector in zip(rows, vectors):
                self._db.execute(_UPSERT, (rel, _vector_to_blob(vector), mtime, title, excerpt, time.time()))
            self._db.commit()
        return len(contents)

    def on_file_changed(self, abs_path_str: str, exists: bool) -> None:
        """The frontmatter index's change listener: mirror one change into this index."""
        if self._db is None or self._model is None:
            return

        try:
            rel = str(Path(abs_path_str).relative_to(config.VAULT_PATH))
        except ValueError:
            return

        path = _readable_note(rel) if exists else None
        if path is None:
            # Gone, or no longer readable (now a hardlink or a symlink, too large).
            with self._lock:
                if self._db is not None:
                    self._db.execute("DELETE FROM embeddings WHERE path = ?", (rel,))
                    self._db.commit()
            return

        try:
            mtime = path.stat().st_mtime
        except OSError:
            return
        self._ingest([(rel, path, mtime)])

    def search(
        self,
        query: str,
        max_results: int,
        min_score: float,
        path_prefix: str | None = None,
    ) -> list[dict]:
        """Embed the query and return the closest notes, best first.

        Each candidate passes the read guard again before it is returned, the way
        vault_search re-checks every match: a note that became unreadable since it was
        indexed is skipped, never served from its stored excerpt.
        """
        if self._model is None or self._db is None:
            return []

        query_vec = self._model.encode(query, show_progress_bar=False, normalize_embeddings=True)

        with self._lock:
            if self._db is None:
                return []
            if path_prefix:
                # Escape LIKE wildcards so a prefix containing % or _ is matched literally.
                escaped = (
                    path_prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                )
                cursor = self._db.execute(
                    "SELECT path, embedding, title, excerpt FROM embeddings "
                    "WHERE path LIKE ? ESCAPE '\\'",
                    (escaped + "%",),
                )
            else:
                cursor = self._db.execute(
                    "SELECT path, embedding, title, excerpt FROM embeddings"
                )
            rows = cursor.fetchall()

        if not rows:
            return []

        # Vectors are stored normalized, so the dot product is the cosine similarity.
        vectors = np.stack([_blob_to_vector(row[1]) for row in rows])
        similarities = vectors @ query_vec

        results = []
        for idx in np.argsort(similarities)[::-1]:
            score = float(similarities[idx])
            if score < min_score:
                break
            path, _, title, excerpt = rows[idx]
            if _readable_note(path) is None:
                continue
            results.append({
                "path": path,
                "score": round(score, 4),
                "title": title,
                "excerpt": excerpt,
            })
            if len(results) >= max_results:
                break

        return results
