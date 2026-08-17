"""Secret-free request context shared by authentication and MCP dispatch."""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Stable authorization metadata for one validated bearer."""

    principal_id: str
    credential_id: str
    client_id: str | None
    policy: str
    capabilities: frozenset[str]
    full_access: bool


@dataclass(frozen=True)
class RequestContext:
    """Metadata bound to one authenticated request."""

    principal: AuthenticatedPrincipal
    request_id: str


_request_context: ContextVar[RequestContext | None] = ContextVar(
    "request_context",
    default=None,
)


def set_request_context(
    principal: AuthenticatedPrincipal,
    request_id: str,
) -> Token[RequestContext | None]:
    """Bind validated metadata for the current request."""
    return _request_context.set(
        RequestContext(principal=principal, request_id=request_id)
    )


def reset_request_context(token: Token[RequestContext | None]) -> None:
    """Restore the previous request context."""
    _request_context.reset(token)


def current_request_context() -> RequestContext | None:
    """Return the current request metadata, if authentication bound one."""
    return _request_context.get()


def current_principal() -> AuthenticatedPrincipal | None:
    """Return the current authenticated principal without credential material."""
    context = current_request_context()
    return context.principal if context is not None else None
