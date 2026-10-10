"""Embedding index for vault_semantic_search.

Each .md note is embedded whole with sentence-transformers (all-MiniLM-L6-v2) and the vector
is stored in SQLite, so the index survives restarts. A query is embedded the same way and
compared against every stored vector: brute-force cosine similarity, fast enough for a
personal vault of a few thousand notes.

Every file the index reads passes the read tools' guard (see _readable_note), and every
result passes it again before it is returned. The database holds an excerpt of every note,
so it is created 0600 in a 0700 directory.
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

# The model and the table layout below are the index's compatibility contract: an index
# written with them is reused as it is. Changing either means embedding every note again.
EMBEDDING_MODEL = "all-MiniLM-L6-v2"


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

    # Skip YAML frontmatter
    body_start = 0
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                body_start = i + 1
                break

    # Collect non-empty, non-heading lines
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
    components, no hardlinks) plus the rules of vault_search's walk, which skips excluded
    directories and never follows a symlink. Applying the walk's rules here too means a
    change event cannot bring in a file the walk would never surface. Only .md notes up to
    MAX_CONTENT_SIZE are indexed. Checked on every read and again on every result.
    """
    if Path(rel).suffix != ".md" or config.EXCLUDED_DIRS & set(Path(rel).parts):
        return None
    try:
        path = resolve_vault_read_path(rel)
        # Resolved anywhere but at its own vault path: a symlink somewhere below the root.
        if path != config.VAULT_PATH.resolve() / rel:
            return None
        if path.stat().st_size > config.MAX_CONTENT_SIZE:
            return None
    except (ValueError, OSError):
        return None
    return path


def _tighten_files(db_path: Path) -> None:
    """Create the database 0600 in a 0700 directory, the way the OAuth store does.

    SQLite gives the WAL and shared-memory files it creates the database's mode. Ones an
    earlier, looser install left behind are tightened here as well.
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
        self._lock = threading.Lock()
        # Serializes reconcile passes so a periodic run and the startup run never overlap
        # (the DB connection and the stale set are shared state).
        self._reconcile_lock = threading.Lock()
        self._db: sqlite3.Connection | None = None

    def start(self) -> None:
        """Open the database, load the embedding model, and bring the index up to date."""
        t0 = time.monotonic()

        db_path = config.VAULT_SEMANTIC_DB_PATH.expanduser()
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
        """Close the SQLite database."""
        if self._db is not None:
            self._db.close()
            self._db = None

    def reconcile(self) -> None:
        """Embed any notes new or modified since the last pass; drop ones gone or refused.

        Idempotent and safe to call repeatedly: at startup, on the periodic floor, or after
        a missed event. Non-overlapping: a second concurrent call returns immediately
        rather than racing the first on the shared DB.
        """
        if self._db is None or self._model is None:
            return
        if not self._reconcile_lock.acquire(blocking=False):
            logger.debug("reconcile already running; skipping overlapping pass")
            return
        try:
            self._reconcile_impl()
        finally:
            self._reconcile_lock.release()

    def _reconcile_impl(self) -> None:
        t0 = time.monotonic()

        cursor = self._db.execute("SELECT path, mtime FROM embeddings")
        db_mtimes = {row[0]: row[1] for row in cursor.fetchall()}

        to_embed = []
        current_paths = set()

        for file_path in _iter_vault_files(config.VAULT_PATH, "*.md"):
            rel = str(file_path.relative_to(config.VAULT_PATH))
            path = _readable_note(rel)
            if path is None:
                continue
            try:
                file_mtime = path.stat().st_mtime
            except OSError:
                continue
            current_paths.add(rel)
            if rel not in db_mtimes or file_mtime > db_mtimes[rel]:
                to_embed.append((rel, path, file_mtime))

        # Remove entries for notes that are gone or no longer readable (an index built
        # without the read guard can hold either). current_paths was snapshotted above, so
        # re-check under the lock: a note that became readable mid-pass (a live event may
        # already have embedded it) must not be dropped.
        stale = set(db_mtimes.keys()) - current_paths
        if stale:
            removed = 0
            with self._lock:
                for rel in stale:
                    if _readable_note(rel) is not None:
                        continue
                    self._db.execute("DELETE FROM embeddings WHERE path = ?", (rel,))
                    removed += 1
                self._db.commit()
            if removed:
                logger.info("Removed %d stale embedding entries", removed)

        if not to_embed:
            elapsed = time.monotonic() - t0
            logger.info("Embedding index up to date (%d files, %.2fs)", len(current_paths), elapsed)
            return

        # Batch embed
        contents = []
        metadata = []
        for rel, path, file_mtime in to_embed:
            try:
                content = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            contents.append(content)
            metadata.append((rel, file_mtime, _extract_title(content, rel), _extract_excerpt(content)))

        if contents:
            vectors = self._model.encode(contents, show_progress_bar=False, normalize_embeddings=True)
            written = 0
            with self._lock:
                for i, (rel, file_mtime, title, excerpt) in enumerate(metadata):
                    # Lost-update guard: content was read and encoded OUTSIDE the lock, so
                    # a live on_file_changed() may have landed a newer version meanwhile.
                    # Skip if the stored row is already at least as new as what this pass read.
                    row = self._db.execute(
                        "SELECT mtime FROM embeddings WHERE path = ?", (rel,)
                    ).fetchone()
                    if row is not None and row[0] is not None and row[0] >= file_mtime:
                        continue
                    self._db.execute(
                        "INSERT OR REPLACE INTO embeddings (path, embedding, mtime, title, excerpt, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (rel, _vector_to_blob(vectors[i]), file_mtime, title, excerpt, time.time()),
                    )
                    written += 1
                self._db.commit()

            elapsed = time.monotonic() - t0
            logger.info(
                "Embedding index reconciled: %d written, %d total files in %.2fs",
                written, len(current_paths), elapsed,
            )

    def on_file_changed(self, abs_path_str: str, exists: bool) -> None:
        """Mirror one change the frontmatter index's watcher saw (its change listener)."""
        if self._db is None or self._model is None:
            return

        try:
            rel = str(Path(abs_path_str).relative_to(config.VAULT_PATH))
        except ValueError:
            return

        # Gone, or no longer readable (now a hardlink or a symlink, too large): drop the row.
        path = _readable_note(rel) if exists else None
        if path is None:
            with self._lock:
                self._db.execute("DELETE FROM embeddings WHERE path = ?", (rel,))
                self._db.commit()
            return

        try:
            # The mtime is taken before the read, as in reconcile, so an edit landing
            # between the two is picked up by the next pass rather than masked by it.
            file_mtime = path.stat().st_mtime
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            return

        title = _extract_title(content, rel)
        excerpt = _extract_excerpt(content)
        vector = self._model.encode(content, show_progress_bar=False, normalize_embeddings=True)

        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO embeddings (path, embedding, mtime, title, excerpt, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (rel, _vector_to_blob(vector), file_mtime, title, excerpt, time.time()),
            )
            self._db.commit()

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
            if path_prefix:
                # Escape LIKE wildcards so a prefix containing % or _ is matched
                # literally (a leading-edge prefix, not a broadened pattern).
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
