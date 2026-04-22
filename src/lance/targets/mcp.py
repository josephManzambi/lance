"""MCP server target adapter.

v0.1 implementation: connect to a local MCP server via the stdio transport
from the official MCP Python SDK. The target exposes the server's tools as
``TargetContext.available_tools`` and satisfies the :class:`Target` protocol.

Semantics of :meth:`MCPTarget.interact` in v0.1 (no LLM in the loop yet):
    * Pick the server's first tool.
    * Call it with ``user_input`` bound to the tool's single string parameter.
    * Return a :class:`TargetTurn` whose ``response`` is the concatenated
      text content of the tool result and whose ``tool_calls`` records the
      single invocation.

Future milestones will wrap an LLM-backed agent adapter around this to turn
``interact`` into a proper agentic round-trip.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import CallToolResult, TextContent

from lance.targets.base import (
    Target,
    TargetContext,
    TargetTurn,
    TargetUnreachableError,
)

if TYPE_CHECKING:
    from lance.targets.config import TargetConfig


class MCPTarget:
    """Target adapter for an MCP server over the stdio transport."""

    def __init__(self, context: TargetContext, params: StdioServerParameters) -> None:
        """Store the context and server parameters; session is opened lazily."""
        self._context = context
        self._params = params
        self._stack: contextlib.AsyncExitStack | None = None
        self._session: ClientSession | None = None

    @property
    def context(self) -> TargetContext:
        """Return the static TargetContext populated at ``from_config`` time."""
        return self._context

    @classmethod
    async def from_config(cls, config: TargetConfig) -> MCPTarget:
        """Start the MCP server subprocess and populate TargetContext.

        Opens a stdio session, calls ``list_tools``, and returns a target
        with the session still alive. Callers are responsible for
        :meth:`aclose`-ing the returned target.
        """
        if not config.command:
            raise TargetUnreachableError("TargetConfig.command is empty; cannot spawn MCP server.")

        params = StdioServerParameters(
            command=config.command[0],
            args=list(config.command[1:]),
        )

        stack = contextlib.AsyncExitStack()
        try:
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            tools_result = await session.list_tools()
        except Exception as err:
            await stack.aclose()
            raise TargetUnreachableError(
                f"Failed to start MCP server with command {config.command!r}: {err}"
            ) from err

        context = TargetContext(
            target_type=config.type,
            target_id=config.target_id,
            available_tools=[tool.name for tool in tools_result.tools],
            iam_role_arn=config.deployment.iam_role_arn,
            metadata={"transport": config.transport, "host": config.host},
        )
        target = cls(context, params)
        target._stack = stack
        target._session = session
        return target

    async def interact(self, user_input: str) -> TargetTurn:
        """Invoke the server's first tool with ``user_input`` and return a TargetTurn.

        Raises:
            TargetUnreachableError: if the session is closed or no tool is
                exposed by the server.
        """
        session = self._require_session()
        if not self._context.available_tools:
            raise TargetUnreachableError(
                f"MCP server {self._context.target_id!r} exposes no tools; cannot interact."
            )
        tool_name = self._context.available_tools[0]
        arg_name = await self._resolve_primary_arg_name(tool_name)
        arguments: dict[str, Any] = {arg_name: user_input}
        result = await session.call_tool(tool_name, arguments=arguments)

        response_text = _extract_text(result)
        tool_calls: list[dict[str, object]] = [
            {
                "name": tool_name,
                "arguments": arguments,
                "is_error": bool(result.isError),
                "result": response_text,
            }
        ]
        return TargetTurn(
            input=user_input,
            response=response_text,
            tool_calls=tool_calls,
            raw_transcript=None,
        )

    async def reset(self) -> None:
        """Terminate and restart the MCP session to clear per-run state."""
        await self._close_stack()
        stack = contextlib.AsyncExitStack()
        try:
            read, write = await stack.enter_async_context(stdio_client(self._params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
        except Exception as err:
            await stack.aclose()
            raise TargetUnreachableError(f"Failed to reset MCP session: {err}") from err
        self._stack = stack
        self._session = session

    async def aclose(self) -> None:
        """Close the MCP session. Safe to call multiple times."""
        await self._close_stack()

    async def _close_stack(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack = None
        self._session = None

    def _require_session(self) -> ClientSession:
        if self._session is None:
            raise TargetUnreachableError(
                "MCP session is not open. Construct via MCPTarget.from_config()."
            )
        return self._session

    async def _resolve_primary_arg_name(self, tool_name: str) -> str:
        """Return the first required parameter name from the tool's inputSchema.

        Falls back to the first property name or ``"input"`` if nothing matches.
        """
        session = self._require_session()
        tools_result = await session.list_tools()
        tool = next((t for t in tools_result.tools if t.name == tool_name), None)
        if tool is None:
            raise TargetUnreachableError(f"Tool {tool_name!r} disappeared from MCP server.")

        schema = tool.inputSchema or {}
        required = schema.get("required")
        if isinstance(required, list) and required and isinstance(required[0], str):
            return required[0]
        properties = schema.get("properties")
        if isinstance(properties, dict) and properties:
            first_key = next(iter(properties))
            if isinstance(first_key, str):
                return first_key
        return "input"


def _extract_text(result: CallToolResult) -> str:
    """Concatenate the text blocks of a tool-call result; empty string if none."""
    parts: list[str] = []
    for block in result.content:
        if isinstance(block, TextContent):
            parts.append(block.text)
    return "\n".join(parts)


_: type[Target] = MCPTarget
