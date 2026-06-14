"""Request-scoped context shared by the bearer middleware and the audit log.

The middleware records, per authenticated request, the principal (the bearer token), a
generated request id, and a best-effort client hint. The audit module reads them when
building a record. It lives in its own module so auth.py (the writer) and audit.py (the
reader) share one ContextVar without importing each other.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any

# A single context var carrying the per-request audit context. Threading the principal
# to the tool layer this way -- rather than as a function argument -- keeps every tool
# signature untouched and works through FastMCP's call path.
_request_context: ContextVar[dict[str, Any] | None] = ContextVar("request_context", default=None)


def set_request_context(principal: str | None, request_id: str | None, client: str | None) -> Token:
    """Bind the audit context for the current request. Returns a reset token."""
    return _request_context.set(
        {"principal": principal, "request_id": request_id, "client": client}
    )


def reset_request_context(token: Token) -> None:
    """Restore the previous audit context (call in a finally block)."""
    _request_context.reset(token)


def current_request_context() -> dict[str, Any]:
    """Return the current request's audit context, or an empty dict outside a request."""
    return _request_context.get() or {}
