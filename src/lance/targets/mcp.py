"""MCP server target adapter.

v0.1 implementation: connect to a local MCP server via stdio or HTTP,
send user inputs through the server's LLM interface, capture tool calls
and responses. TargetContext is populated from the server's tool manifest
and an optional deployment-context config.

Status: stub.
"""

from __future__ import annotations

from lance.targets.base import Target, TargetContext, TargetTurn


class MCPTarget:
    """Target adapter for an MCP server. Implementation pending v0.1."""

    def __init__(self, context: TargetContext) -> None:
        self._context = context

    @property
    def context(self) -> TargetContext:
        return self._context

    async def interact(self, user_input: str) -> TargetTurn:
        raise NotImplementedError("MCPTarget.interact — pending v0.1.")

    async def reset(self) -> None:
        raise NotImplementedError("MCPTarget.reset — pending v0.1.")


# Runtime-check: MCPTarget satisfies the Target protocol.
_: type[Target] = MCPTarget  # type: ignore[assignment]
