"""Principal-aware MCP discovery, dispatch, and tool registration."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ResourceError, ToolError

from .context import current_principal


class PolicyFastMCP(FastMCP):
    """FastMCP server that enforces request-principal capabilities."""

    def __init__(self, *args, **kwargs) -> None:
        self._required_tool_capabilities: dict[str, str] = {}
        super().__init__(*args, **kwargs)

    def record_tool_capability(self, tool_name: str, capability: str) -> None:
        """Bind one registered tool to the capability required to discover/call it."""
        if not capability:
            raise ValueError("tool capability must not be empty")
        self._required_tool_capabilities[tool_name] = capability

    def required_capability(self, tool_name: str) -> str | None:
        """Return the recorded capability, or None for an unclassified tool."""
        return self._required_tool_capabilities.get(tool_name)

    def _tool_allowed(self, tool_name: str) -> bool:
        principal = current_principal()
        if principal is None:
            return False
        if principal.full_access:
            return True
        required = self.required_capability(tool_name)
        return required is not None and required in principal.capabilities

    @staticmethod
    def _full_access() -> bool:
        principal = current_principal()
        return principal is not None and principal.full_access

    async def list_tools(self):
        """Return only tools authorized for the current principal."""
        tools = await super().list_tools()
        return [tool for tool in tools if self._tool_allowed(tool.name)]

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> Sequence[Any] | dict[str, Any]:
        """Reject unauthorized dispatch before invoking tool code."""
        if not self._tool_allowed(name):
            raise ToolError("Forbidden: tool is not permitted for this principal")
        return await super().call_tool(name, arguments)

    async def list_resources(self):
        """Resources remain unavailable to capability-limited principals."""
        return await super().list_resources() if self._full_access() else []

    async def list_resource_templates(self):
        """Resource templates remain unavailable to restricted principals."""
        return await super().list_resource_templates() if self._full_access() else []

    async def read_resource(self, uri) -> Iterable[Any]:
        """Deny direct resource reads before resource resolution."""
        if not self._full_access():
            raise ResourceError(
                "Forbidden: resources are not permitted for this principal"
            )
        return await super().read_resource(uri)

    async def list_prompts(self):
        """Prompts remain unavailable to capability-limited principals."""
        return await super().list_prompts() if self._full_access() else []

    async def get_prompt(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ):
        """Deny direct prompt access before rendering."""
        if not self._full_access():
            raise ValueError("Forbidden: prompts are not permitted for this principal")
        return await super().get_prompt(name, arguments)


class ToolRegistrar:
    """Narrow policy-aware registration surface for core and extension tools."""

    __slots__ = ("_server",)

    def __init__(self, server: PolicyFastMCP) -> None:
        self._server = server

    def tool(
        self,
        name: str | None = None,
        title: str | None = None,
        description: str | None = None,
        annotations: Any | None = None,
        icons: list[Any] | None = None,
        meta: dict[str, Any] | None = None,
        structured_output: bool | None = None,
        *,
        required_capability: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Register a tool; its final name is the default required capability."""
        if callable(name):
            raise TypeError("Use @tool() rather than @tool when registering a tool")

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            effective_name = name or fn.__name__
            capability = required_capability or effective_name
            self._server.add_tool(
                fn,
                name=name,
                title=title,
                description=description,
                annotations=annotations,
                icons=icons,
                meta=meta,
                structured_output=structured_output,
            )
            self._server.record_tool_capability(effective_name, capability)
            return fn

        return decorator
