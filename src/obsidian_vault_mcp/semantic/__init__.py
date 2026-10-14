"""Optional semantic search: vault_semantic_search (VAULT_SEMANTIC_SEARCH).

Off by default. server.serve() imports this package only when the operator switches it on,
calls require_dependencies() so a missing extra fails startup with an install hint, and
only then imports .extension, which needs numpy and sentence-transformers. This module
itself imports neither.
"""


def require_dependencies() -> None:
    """Import the semantic-search libraries, raising RuntimeError with install guidance if absent.

    Called once at startup so a server with the feature on and the extra missing fails
    CLOSED with a clear message, instead of crashing midway through starting up.
    """
    try:
        import numpy  # noqa: F401
        import sentence_transformers  # noqa: F401
    except Exception as e:
        raise RuntimeError(
            "Semantic search is enabled (VAULT_SEMANTIC_SEARCH) but its dependencies are "
            "missing. Install them with: pip install 'obsidian-web-mcp[semantic]'"
        ) from e
