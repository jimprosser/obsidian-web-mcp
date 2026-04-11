"""In-memory index of YAML frontmatter across all vault .md files."""

import logging
import threading
import time
from pathlib import Path

import frontmatter
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from . import config

logger = logging.getLogger(__name__)


class FrontmatterIndex:
    """Thread-safe in-memory index of YAML frontmatter for fast queries."""

    def __init__(self) -> None:
        self._index: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._observer: Observer | None = None
        self._debounce_timer: threading.Timer | None = None
        self._pending_paths: set[str] = set()

    def start(self) -> None:
        """Walk all .md files, parse frontmatter, and start watching for changes."""
        # Defensive guard: the observer is a process-wide singleton. Re-entering
        # start() would double-schedule the same FSEvents watch and crash.
        if self._observer is not None:
            return

        t0 = time.monotonic()
        count = 0

        for md_path in config.VAULT_PATH.rglob("*.md"):
            if self._is_excluded(md_path):
                continue
            rel = str(md_path.relative_to(config.VAULT_PATH))
            fm = self._parse_frontmatter(md_path)
            if fm is not None:
                self._index[rel] = fm
                count += 1

        elapsed = time.monotonic() - t0
        logger.info(
            "Frontmatter index built: %d files in %.2f seconds", count, elapsed
        )

        self._observer = Observer()
        handler = _VaultEventHandler(self)
        self._observer.schedule(handler, str(config.VAULT_PATH), recursive=True)
        self._observer.start()

    def stop(self) -> None:
        """Stop the filesystem observer and cancel any pending debounce."""
        if self._debounce_timer is not None:
            self._debounce_timer.cancel()
            self._debounce_timer = None
        if self._observer is not None:
            self._observer.stop()
            self._observer.join()
            self._observer = None

    @property
    def file_count(self) -> int:
        with self._lock:
            return len(self._index)

    def search_by_field(
        self,
        field: str,
        value: str,
        match_type: str,
        path_prefix: str | None = None,
    ) -> list[dict]:
        """Search frontmatter index by field.

        Args:
            field: Frontmatter key to match against.
            value: Value to compare (ignored for match_type "exists").
            match_type: One of "exact", "contains", "exists".
            path_prefix: If set, only return files whose relative path starts with this.

        Returns:
            List of {"path": relative_path, "frontmatter": dict}.
        """
        results: list[dict] = []
        with self._lock:
            for rel_path, fm in self._index.items():
                if path_prefix and not rel_path.startswith(path_prefix):
                    continue
                if match_type == "exists":
                    if field in fm:
                        results.append({"path": rel_path, "frontmatter": fm})
                elif match_type == "exact":
                    if field in fm and str(fm[field]) == value:
                        results.append({"path": rel_path, "frontmatter": fm})
                elif match_type == "contains":
                    if field in fm and value.lower() in str(fm[field]).lower():
                        results.append({"path": rel_path, "frontmatter": fm})
        return results

    # -- Internal helpers --

    def _is_excluded(self, path: Path) -> bool:
        """Check whether any path component is in config.EXCLUDED_DIRS."""
        return bool(config.EXCLUDED_DIRS & set(path.relative_to(config.VAULT_PATH).parts))

    def _parse_frontmatter(self, path: Path) -> dict | None:
        """Parse YAML frontmatter from a markdown file. Returns None on failure."""
        try:
            post = frontmatter.load(str(path))
            return dict(post.metadata)
        except Exception:
            logger.warning("Failed to parse frontmatter: %s", path)
            return None

    def _schedule_debounce(self, abs_path: str) -> None:
        """Add a path to the pending set and reset the debounce timer."""
        with self._lock:
            self._pending_paths.add(abs_path)
            if self._debounce_timer is not None:
                self._debounce_timer.cancel()
            self._debounce_timer = threading.Timer(
                config.FRONTMATTER_INDEX_DEBOUNCE, self._flush_pending
            )
            self._debounce_timer.start()

    def _flush_pending(self) -> None:
        """Process all pending file changes."""
        with self._lock:
            paths = self._pending_paths.copy()
            self._pending_paths.clear()
            self._debounce_timer = None

        for abs_path_str in paths:
            abs_path = Path(abs_path_str)
            rel = str(abs_path.relative_to(config.VAULT_PATH))
            if abs_path.exists():
                fm = self._parse_frontmatter(abs_path)
                with self._lock:
                    if fm is not None:
                        self._index[rel] = fm
                    else:
                        self._index.pop(rel, None)
            else:
                with self._lock:
                    self._index.pop(rel, None)


class _VaultEventHandler(FileSystemEventHandler):
    """Watchdog handler that feeds .md changes into the frontmatter index."""

    def __init__(self, index: FrontmatterIndex) -> None:
        super().__init__()
        self._index = index

    def _handle(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix != ".md":
            return
        if self._index._is_excluded(path):
            return
        self._index._schedule_debounce(event.src_path)

    def on_created(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._handle(event)
