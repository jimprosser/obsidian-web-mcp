"""SemanticExtension: the built-in extension behind vault_semantic_search.

server.serve() adds it ahead of the operator's own extensions when VAULT_SEMANTIC_SEARCH is
on, once require_dependencies() has found the `semantic` extra. It uses the same seam a
downstream extension would:

register_tools         -> add vault_semantic_search, declared to the audit log as a read
before_indexes_start   -> load the model, bring the index up to date, and attach its
                          listener to the frontmatter index BEFORE that starts watching
after_indexes_start    -> start the reconcile loop
shutdown               -> stop the reconcile loop + close the embedding DB
"""

import logging
import threading

from pydantic import BaseModel, ConfigDict, Field

from ..audit import register_audit_operation, run_audited
from ..extensions import Extension
from ..serialization import dumps
from .index import EmbeddingIndex

logger = logging.getLogger(__name__)

# Result-count and score bounds for the tool.
MAX_SEMANTIC_RESULTS = 20
DEFAULT_SEMANTIC_RESULTS = 10
DEFAULT_MIN_SCORE = 0.3

# Self-healing floor under the file watcher. The macOS FSEvents emitter can die silently
# (watchdog raises "Cannot add watch ... it is already scheduled" and the emitter returns
# before reading events), after which no change reaches the index for the life of the
# process. Re-running the idempotent reconcile on this interval turns a dead watcher into
# bounded staleness instead of an index that never changes again.
RECONCILE_INTERVAL = 600.0

_DESCRIPTION = (
    "Search vault files by semantic similarity to a natural language query. "
    "Complements vault_search (keyword/ripgrep) for fuzzy or conceptual queries "
    "where you don't know the exact keyword. Returns results ranked by cosine "
    "similarity with excerpts. Each note is matched on its opening (roughly the first "
    "256 tokens), so for a passage deep inside a long note use vault_search."
)


class VaultSemanticSearchInput(BaseModel):
    """Semantic search across vault files using vector similarity."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    query: str = Field(
        ...,
        description="Natural language query (e.g. 'crisis communications strategy')",
        min_length=1,
        max_length=500,
    )
    max_results: int = Field(
        default=DEFAULT_SEMANTIC_RESULTS,
        ge=1,
        le=MAX_SEMANTIC_RESULTS,
        description="Maximum number of results to return",
    )
    min_score: float = Field(
        default=DEFAULT_MIN_SCORE,
        ge=0.0,
        le=1.0,
        description="Minimum cosine similarity score (0-1) for a result to be returned",
    )
    path_prefix: str | None = Field(
        default=None,
        max_length=500,
        description="If set, restrict results to files whose path starts with this prefix",
    )


def _vault_semantic_search(index: EmbeddingIndex, inp: VaultSemanticSearchInput) -> str:
    try:
        results = index.search(inp.query, inp.max_results, inp.min_score, inp.path_prefix)
        return dumps({"results": results, "total": len(results), "query": inp.query})
    except Exception as e:
        logger.error("vault_semantic_search error: %s", e)
        return dumps({"error": str(e)})


class SemanticExtension(Extension):
    def __init__(self) -> None:
        self._index = EmbeddingIndex()
        self._stop = threading.Event()
        self._reconcile: threading.Thread | None = None

    def register_tools(self, mcp) -> None:
        # A read, so it is recorded when VAULT_AUDIT_LOG_INCLUDE_READS is on, like vault_search.
        register_audit_operation("vault_semantic_search", kind="read")
        index = self._index

        @mcp.tool(
            name="vault_semantic_search",
            description=_DESCRIPTION,
            annotations={
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        )
        def vault_semantic_search(
            query: str,
            max_results: int = DEFAULT_SEMANTIC_RESULTS,
            min_score: float = DEFAULT_MIN_SCORE,
            path_prefix: str | None = None,
        ) -> str:
            """Semantic search across vault files."""
            inp = VaultSemanticSearchInput(
                query=query, max_results=max_results, min_score=min_score, path_prefix=path_prefix
            )
            return run_audited("vault_semantic_search", lambda: _vault_semantic_search(index, inp))

    def before_indexes_start(self, frontmatter_index) -> None:
        # Load the model and reconcile first, then attach the listener BEFORE the
        # frontmatter index starts watching, so no change is missed between build and attach.
        self._index.start()
        frontmatter_index.add_change_listener(self._index.on_file_changed)

    def after_indexes_start(self, frontmatter_index) -> None:
        self._reconcile = threading.Thread(
            target=self._reconcile_forever, name="semantic-reconcile", daemon=True
        )
        self._reconcile.start()
        logger.info("Semantic search enabled (reconcile every %.0fs)", RECONCILE_INTERVAL)

    def _reconcile_forever(self) -> None:
        # wait() blocks for the interval and returns False; it returns True only once
        # shutdown() sets the event, which ends the loop. A pass that raises is logged and
        # the loop keeps going, so one bad pass never stalls the floor.
        while not self._stop.wait(RECONCILE_INTERVAL):
            try:
                self._index.reconcile()
            except Exception:
                logger.exception("Embedding reconcile failed")

    def shutdown(self) -> None:
        self._stop.set()
        if self._reconcile is not None:
            self._reconcile.join(timeout=30)
            self._reconcile = None
        self._index.stop()
