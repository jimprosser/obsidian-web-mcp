"""SemanticExtension: the built-in extension behind vault_semantic_search.

server.serve() adds it ahead of the operator's own extensions when VAULT_SEMANTIC_SEARCH is
on and require_dependencies() has found the `semantic` extra.
"""

import logging
import threading

from pydantic import BaseModel, ConfigDict, Field

from ..audit import register_audit_operation, run_audited
from ..extensions import Extension
from ..serialization import dumps
from .index import EmbeddingIndex

logger = logging.getLogger(__name__)

MAX_SEMANTIC_RESULTS = 20
DEFAULT_SEMANTIC_RESULTS = 10
DEFAULT_MIN_SCORE = 0.3

# The floor under the file watcher: watchdog's macOS FSEvents emitter can die silently
# ("Cannot add watch ... already scheduled"), and nothing would reach the index again.
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
        self._index.start()
        # Attached before the frontmatter index starts watching, so no change is missed.
        frontmatter_index.add_change_listener(self._index.on_file_changed)

    def after_indexes_start(self, frontmatter_index) -> None:
        self._reconcile = threading.Thread(
            target=self._reconcile_forever, name="semantic-reconcile", daemon=True
        )
        self._reconcile.start()
        logger.info("Semantic search enabled (reconcile every %.0fs)", RECONCILE_INTERVAL)

    def _reconcile_forever(self) -> None:
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
